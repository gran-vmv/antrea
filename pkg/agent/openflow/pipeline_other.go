// +build !windows
// package openflow is needed by antctl which is compiled for macOS too.

// Copyright 2021 Antrea Authors
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

package openflow

import (
	"net"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/openflow/cookie"
	binding "antrea.io/antrea/pkg/ovs/openflow"
)

func (c *client) snatMarkFlows(snatIP net.IP, mark uint32) []binding.Flow {
	return []binding.Flow{c.snatIPFromTunnelFlow(snatIP, mark)}
}

func (c *client) l3FwdFlowToRemoteViaRouting(localGatewayMAC net.HardwareAddr, remoteGatewayMAC net.HardwareAddr,
	category cookie.Category, peerIP net.IP, peerPodCIDR *net.IPNet) []binding.Flow {
	if c.enableBridge && c.encapMode.NeedsDirectRoutingToPeer(peerIP, c.nodeConfig.NodeTransportIPAddr) && remoteGatewayMAC != nil {
		ipProto := getIPProtocol(peerIP)
		l3FwdTable := c.pipeline[l3ForwardingTable]
		// It enhances Noencap mode performance by bypassing host network.
		flows := []binding.Flow{c.pipeline[l2ForwardingCalcTable].BuildFlow(priorityNormal).
			MatchDstMAC(remoteGatewayMAC).
			Action().LoadRegRange(int(PortCacheReg), config.UplinkOFPort, ofPortRegRange).
			Action().LoadRegRange(int(marksReg), macRewriteMark, ofPortMarkRange).
			Action().GotoTable(conntrackCommitTable).
			Cookie(c.cookieAllocator.Request(category).Raw()).
			Done(),
			// Output the reply packet to the uplink interface if the destination is another Node's IP.
			// This is for the scenario that another Node directly accesses Pods on this Node. Since the request
			// packet enters OVS from the uplink interface, the reply should go back in the same path.
			l3FwdTable.BuildFlow(priorityNormal).MatchProtocol(ipProto).
				MatchDstIP(peerIP).
				MatchCTStateRpl(true).MatchCTStateTrk(true).
				Action().SetDstMAC(remoteGatewayMAC).
				Action().GotoTable(l3FwdTable.GetNext()).
				Cookie(c.cookieAllocator.Request(category).Raw()).
				Done(),
		}
		flows = append(flows, c.l3FwdFlowToRemoteViaGW(remoteGatewayMAC, *peerPodCIDR, category))
		return flows
	}
	return []binding.Flow{c.l3FwdFlowToRemoteViaGW(localGatewayMAC, *peerPodCIDR, category)}
}
