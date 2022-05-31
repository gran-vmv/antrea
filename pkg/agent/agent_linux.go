//go:build linux
// +build linux

// Copyright 2020 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package agent

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	utilip "antrea.io/antrea/pkg/util/ip"
)

// prepareHostNetwork returns immediately on Linux.
func (i *Initializer) prepareHostNetwork() error {
	return nil
}

func (i *Initializer) prepareOVSBridge() error {
	// Return immediately on Linux if connectUplinkToBridge is false.
	if !i.connectUplinkToBridge {
		return nil
	}
	klog.Infof("Preparing OVS bridge for AntreaFlexibleIPAM")
	// Get uplink network configuration.
	// TODO(gran): support IPv6
	brName := i.ovsBridgeClient.GetBridgeName()
	_, _, adapter, err := i.getNodeInterfaceFromIP(&utilip.DualStackIPs{IPv4: i.nodeConfig.NodeIPv4Addr.IP})
	if err != nil {
		return err
	}
	uplinkNetConfig := i.nodeConfig.UplinkNetConfig
	uplinkNetConfig.OriginalName = adapter.Name
	if uplinkNetConfig.OriginalName == brName {
		// case 1: uplink name == brName
		// case 2: local port is already added to OVS
		// case 2 will be handled below
		uplinkNetConfig.Name = util.ParseBridgedUplinkName(adapter.Name)
	} else {
		uplinkNetConfig.Name = adapter.Name
	}
	uplinkNetConfig.MAC = adapter.HardwareAddr
	uplinkNetConfig.IP = i.nodeConfig.NodeIPv4Addr
	uplinkNetConfig.Index = adapter.Index
	// Gateway and DNSServers are not configured at adapter in Linux
	// Limitation: dynamic DNS servers will be lost after DHCP lease expired
	uplinkNetConfig.Gateway = ""
	uplinkNetConfig.DNSServers = ""
	// Save routes which are configured on the uplink interface.
	// The routes on the host will be lost when moving the network configuration of the uplink interface
	// to the OVS bridge local interface. The saved routes will be restored on host after that.
	if err = i.saveHostRoutes(); err != nil {
		return err
	}

	// Set datapathID of OVS bridge.
	// If no datapathID configured explicitly, the reconfiguration operation will change OVS bridge datapathID
	// and break the OpenFlow channel.
	// The length of datapathID is 64 bits, the lower 48-bits are for a MAC address, while the upper 16-bits are
	// implementer-defined. Antrea uses "0x0000" for the upper 16-bits.
	datapathID := strings.Replace(uplinkNetConfig.MAC.String(), ":", "", -1)
	datapathID = "0000" + datapathID
	if err = i.ovsBridgeClient.SetDatapathID(datapathID); err != nil {
		return fmt.Errorf("failed to set datapath_id %s: err=%w", datapathID, err)
	}

	// case 2
	if _, err = i.ovsBridgeClient.GetOFPort(brName, false); err == nil {
		klog.Infof("OVS bridge local port %s already exists", brName)
		// If local port exists, get the real uplink interface.
		// This branch is used when antrea-agent get a hard restart (e.g. SIGKILL)
		ports, err := i.ovsBridgeClient.GetPortList()
		if err != nil {
			return err
		}
		klog.V(2).Infof("Found ports from OVS bridge: %+v", ports)
		var uplinkPort *ovsconfig.OVSPortData
		for index := range ports {
			if ports[index].OFPort == config.UplinkOFPort {
				uplinkPort = &ports[index]
				break
			}
		}
		if uplinkPort == nil {
			klog.Warningf("Cannot find uplink port from OVS bridge %s", brName)
			return nil
		}
		adapter, err2 := net.InterfaceByName(uplinkPort.Name)
		if err2 != nil {
			return fmt.Errorf("cannot find uplink port %s: err=%w", uplinkPort.Name, err2)
		}
		klog.Infof("Found uplink device %s", adapter.Name)
		uplinkNetConfig.Name = adapter.Name
		uplinkNetConfig.Index = adapter.Index
		uplinkInterface := interfacestore.NewUplinkInterface(uplinkPort.Name)
		uplinkInterface.OVSPortConfig = &interfacestore.OVSPortConfig{uplinkPort.UUID, config.UplinkOFPort} //nolint: govet
		i.ifaceStore.AddInterface(uplinkInterface)
	}
	return nil
}

// getTunnelLocalIP returns local_ip of tunnel port.
// On linux platform, local_ip option is not needed.
func (i *Initializer) getTunnelPortLocalIP() net.IP {
	return nil
}

func GetTransportIPNetDeviceByName(ifaceName string, ovsBridgeName string) (*net.IPNet, *net.IPNet, *net.Interface, error) {
	return util.GetIPNetDeviceByName(ifaceName)
}

// saveHostRoutes saves routes which are configured on uplink interface before
// the interface the configured as the uplink of antrea network.
// The routes will be restored on OVS bridge interface after the IP configuration
// is moved to the OVS bridge.
func (i *Initializer) saveHostRoutes() error {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	for _, route := range routes {
		if route.LinkIndex != i.nodeConfig.UplinkNetConfig.Index {
			klog.V(2).Infof("Skipped host route not on uplink: %+v", route)
			continue
		}
		// Skip IPv6 routes before we support IPv6 stack.
		// TODO(gran): support IPv6
		if route.Gw.To4() == nil {
			klog.V(2).Infof("Skipped IPv6 host route: %+v", route)
			continue
		}
		klog.Infof("Got host route=%+v", route)
		i.nodeConfig.UplinkNetConfig.Routes = append(i.nodeConfig.UplinkNetConfig.Routes, route)
	}
	return nil
}

// restoreHostRoutes restores the host routes which are lost when moving the IP
// configuration of uplink interface to the OVS bridge interface during
// the antrea network initialize stage.
// The backup routes are restored after the IP configuration change.
func (i *Initializer) restoreHostRoutes() error {
	return i.restoreHostRoutesToInterface(i.ovsBridge)
}

func (i *Initializer) restoreHostRoutesToInterface(ifaceName string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil
	}
	for _, routeInterface := range i.nodeConfig.UplinkNetConfig.Routes {
		route := routeInterface.(netlink.Route)
		newRoute := route
		newRoute.LinkIndex = iface.Index
		if err := netlink.RouteReplace(&newRoute); err != nil {
			return err
		}
	}
	return nil
}

func (i *Initializer) ConnectUplinkToOVSBridge() error {
	// Return immediately on Linux if connectUplinkToBridge is false.
	if !i.connectUplinkToBridge {
		return nil
	}
	klog.Infof("Bridging uplink to OVS bridge")
	var err error
	uplinkNetConfig := i.nodeConfig.UplinkNetConfig
	uplinkName := uplinkNetConfig.Name
	uplinkOriginalName := uplinkNetConfig.OriginalName
	brName := i.ovsBridgeClient.GetBridgeName()

	// If uplink is already exists, return.
	if _, err := i.ovsBridgeClient.GetOFPort(uplinkName, false); err == nil {
		klog.Infof("Uplink %s already exists, skip the configuration", uplinkName)
		return nil
	}
	if uplinkName != uplinkOriginalName {
		if err := util.ChangeAdapterName(uplinkOriginalName, uplinkName, true); err != nil {
			return fmt.Errorf("failed to change uplink interface name: err=%w", err)
		}
	}

	// Create uplink port.
	uplinkPortUUID, err := i.ovsBridgeClient.CreateUplinkPort(uplinkName, config.UplinkOFPort, map[string]interface{}{interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaUplink})
	if err != nil {
		return fmt.Errorf("failed to add uplink port %s: err=%w", uplinkName, err)
	}
	// Add newly created uplinkInterface to interface cache. This will be overwritten by initInterfaceStore.
	uplinkInterface := interfacestore.NewUplinkInterface(uplinkName)
	uplinkInterface.OVSPortConfig = &interfacestore.OVSPortConfig{uplinkPortUUID, config.UplinkOFPort} //nolint: govet
	i.ifaceStore.AddInterface(uplinkInterface)

	// Create local port.
	// OVS does not receive "ofport_request" param when creating local port, so here use config.AutoAssignedOFPort=0
	// to ignore this param.
	if _, err = i.ovsBridgeClient.GetOFPort(brName, false); err != nil {
		externalIDs := map[string]interface{}{
			interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaHost,
		}
		if _, err := i.ovsBridgeClient.CreateInternalPort(brName, config.AutoAssignedOFPort, externalIDs); err != nil {
			return fmt.Errorf("failed to add local port %s: err=%w", brName, err)
		}
	}

	// Move network configuration of uplink interface to OVS bridge local interface.
	// The net configuration of uplink will be restored by RestoreOVSBridge when shutting down.
	wait.PollImmediate(100*time.Millisecond, 10000*time.Millisecond, func() (bool, error) {
		// Wait a few seconds for OVS bridge local port.
		link, err := netlink.LinkByName(brName)
		if err != nil {
			klog.V(4).InfoS("OVS bridge local port is not ready", "port", brName, "err", err)
			return false, nil
		}
		klog.InfoS("OVS bridge local port is ready", "type", link.Type(), "attrs", link.Attrs())
		return true, nil
	})
	localLink, err := netlink.LinkByName(brName)
	if err != nil {
		return err
	}
	if _, _, err = util.SetLinkUp(brName); err != nil {
		return err
	}
	if err = util.SetAdapterMACAddress(brName, &uplinkNetConfig.MAC); err != nil {
		return err
	}
	// TODO(gran): support IPv6
	if err = util.ConfigureLinkAddresses(localLink.Attrs().Index, []*net.IPNet{uplinkNetConfig.IP}); err != nil {
		return err
	}
	if err = util.ConfigureLinkAddresses(uplinkNetConfig.Index, nil); err != nil {
		return err
	}
	// Restore the host routes which are lost when moving the network configuration of the uplink interface to OVS bridge interface.
	if err = i.restoreHostRoutes(); err != nil {
		return err
	}

	return nil
}

// RestoreOVSBridge returns immediately on Linux if connectUplinkToBridge is false.
// OVS is managed by Antrea in Linux, network config must be restored to uplink before Antrea Agent shutdown.
func (i *Initializer) RestoreOVSBridge() {
	if !i.connectUplinkToBridge {
		return
	}
	klog.Infof("Restoring bridge config to uplink...")
	uplinkNetConfig := i.nodeConfig.UplinkNetConfig
	uplinkName := ""
	uplinkOriginalName := ""
	if uplinkNetConfig != nil {
		uplinkName = uplinkNetConfig.Name
		uplinkOriginalName = uplinkNetConfig.OriginalName
	}
	brName := i.ovsBridgeClient.GetBridgeName()

	if _, err := i.ovsBridgeClient.GetOFPort(brName, false); err == nil {
		if err := util.DeleteOVSBridge(brName); err != nil {
			klog.ErrorS(err, "Delete OVS bridge failed", "bridge", brName)
		}
	} else {
		klog.Warningf("OVS bridge local port not found: %+v", err)
	}
	if uplinkName != "" {
		if uplinkName != uplinkOriginalName {
			if err := util.ChangeAdapterName(uplinkName, uplinkOriginalName, true); err != nil {
				klog.ErrorS(err, "Restore uplink name failed", "interface", uplinkOriginalName)
			}
		}
		if err := util.ConfigureLinkAddresses(uplinkNetConfig.Index, []*net.IPNet{uplinkNetConfig.IP}); err != nil {
			klog.ErrorS(err, "Configure IP to uplink failed", "uplink", uplinkOriginalName)
		}
		if err := i.restoreHostRoutesToInterface(uplinkOriginalName); err != nil {
			klog.ErrorS(err, "Configure route to uplink interface failed", "interface", uplinkOriginalName)
		}
	}
	klog.Infof("Finished to restore bridge config to uplink...")
}

func (i *Initializer) setInterfaceMTU(iface string, mtu int) error {
	return i.ovsBridgeClient.SetInterfaceMTU(iface, mtu)
}
