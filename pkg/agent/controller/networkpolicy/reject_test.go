// Copyright 2023 Antrea Authors
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

package networkpolicy

import (
	"encoding/binary"
	"github.com/golang/mock/gomock"
	"net"
	"testing"

	"antrea.io/libOpenflow/openflow15"
	"antrea.io/ofnet/ofctrl"

	"antrea.io/antrea/pkg/agent/config"
	"antrea.io/antrea/pkg/agent/openflow"
	binding "antrea.io/antrea/pkg/ovs/openflow"
	mocks "antrea.io/antrea/pkg/ovs/openflow/testing"
)

func Test_parseFlexibleIPAMStatus(t *testing.T) {
	ctZone := uint16(1)
	ctZoneBytes := make([]byte, 8)
	binary.BigEndian.PutUint16(ctZoneBytes, ctZone)
	type args struct {
		pktIn      *ofctrl.PacketIn
		nodeConfig *config.NodeConfig
		srcIP      string
		srcIsLocal bool
		dstIP      string
		dstIsLocal bool
	}
	tests := []struct {
		name                  string
		args                  args
		wantIsFlexibleIPAMSrc bool
		wantIsFlexibleIPAMDst bool
		wantCtZone            uint32
		wantErr               bool
	}{
		{
			name: "NoFlexibleIPAM",
			args: args{
				pktIn:      &ofctrl.PacketIn{},
				nodeConfig: nil,
				srcIP:      "",
				srcIsLocal: false,
				dstIP:      "",
				dstIsLocal: false,
			},
			wantIsFlexibleIPAMSrc: false,
			wantIsFlexibleIPAMDst: false,
			wantCtZone:            0,
			wantErr:               false,
		},
		{
			name: "FlexibleIPAM",
			args: args{
				pktIn: &ofctrl.PacketIn{
					Match: openflow15.Match{
						Type:   0,
						Length: 0,
						Fields: []openflow15.MatchField{{
							Class:          openflow15.OXM_CLASS_PACKET_REGS,
							Field:          4,
							HasMask:        false,
							Length:         0,
							ExperimenterID: 0,
							Value: &openflow15.ByteArrayField{
								Data:   []byte{0, 0, 0, 1, 0, 0, 0, 0},
								Length: 64,
							},
							Mask: nil,
						}},
					},
				},
				nodeConfig: &config.NodeConfig{
					PodIPv4CIDR: &net.IPNet{
						IP:   net.IPv4(1, 2, 2, 0),
						Mask: net.IPv4Mask(255, 255, 255, 0),
					},
				},
				srcIP:      "1.2.3.4",
				srcIsLocal: true,
				dstIP:      "1.2.3.5",
				dstIsLocal: true,
			},
			wantIsFlexibleIPAMSrc: true,
			wantIsFlexibleIPAMDst: true,
			wantCtZone:            1,
			wantErr:               false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIsFlexibleIPAMSrc, gotIsFlexibleIPAMDst, gotCtZone, err := parseFlexibleIPAMStatus(tt.args.pktIn, tt.args.nodeConfig, tt.args.srcIP, tt.args.srcIsLocal, tt.args.dstIP, tt.args.dstIsLocal)
			matches := tt.args.pktIn.GetMatches()
			match := getMatchRegField(matches, openflow.CtZoneField)
			t.Logf("match: %+v", match)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseFlexibleIPAMStatus() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotIsFlexibleIPAMSrc != tt.wantIsFlexibleIPAMSrc {
				t.Errorf("parseFlexibleIPAMStatus() gotIsFlexibleIPAMSrc = %v, want %v", gotIsFlexibleIPAMSrc, tt.wantIsFlexibleIPAMSrc)
			}
			if gotIsFlexibleIPAMDst != tt.wantIsFlexibleIPAMDst {
				t.Errorf("parseFlexibleIPAMStatus() gotIsFlexibleIPAMDst = %v, want %v", gotIsFlexibleIPAMDst, tt.wantIsFlexibleIPAMDst)
			}
			if gotCtZone != tt.wantCtZone {
				t.Errorf("parseFlexibleIPAMStatus() gotCtZone = %v, want %v", gotCtZone, tt.wantCtZone)
			}
		})
	}
}

func Test_getRejectPacketOutMutateFunc(t *testing.T) {
	openflow.InitMockTables(
		map[*openflow.Table]uint8{
			openflow.ConntrackTable:        uint8(5),
			openflow.L3ForwardingTable:     uint8(6),
			openflow.L2ForwardingCalcTable: uint8(7),
		})
	conntrackTableID := openflow.ConntrackTable.GetID()
	l3ForwardingTableID := openflow.L3ForwardingTable.GetID()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	type args struct {
		rejectType        RejectType
		nodeType          config.NodeType
		isFlexibleIPAMSrc bool
		isFlexibleIPAMDst bool
		ctZone            uint32
	}
	tests := []struct {
		name        string
		args        args
		prepareFunc func(builder *mocks.MockPacketOutBuilder)
	}{
		{
			name: "RejectServiceLocalFlexibleIPAMSrc",
			args: args{
				rejectType:        RejectServiceLocal,
				nodeType:          config.K8sNode,
				isFlexibleIPAMSrc: true,
				isFlexibleIPAMDst: false,
				ctZone:            1,
			},
			prepareFunc: func(builder *mocks.MockPacketOutBuilder) {
				builder.EXPECT().AddLoadRegMark(openflow.CustomReasonRejectRegMark).Return(builder)
				builder.EXPECT().AddLoadRegMark(openflow.AntreaFlexibleIPAMRegMark).Return(builder)
				builder.EXPECT().AddLoadRegMark(binding.NewRegMark(openflow.CtZoneField, 1)).Return(builder)
				builder.EXPECT().AddResubmitAction(nil, &conntrackTableID).Return(builder)
			},
		},
		{
			name: "RejectServiceOtherSrc",
			args: args{
				rejectType:        RejectServiceLocal,
				nodeType:          config.K8sNode,
				isFlexibleIPAMSrc: false,
				isFlexibleIPAMDst: false,
				ctZone:            1,
			},
			prepareFunc: func(builder *mocks.MockPacketOutBuilder) {
				builder.EXPECT().AddLoadRegMark(openflow.CustomReasonRejectRegMark).Return(builder)
				builder.EXPECT().AddLoadRegMark(binding.NewRegMark(openflow.CtZoneField, 1)).Return(builder)
				builder.EXPECT().AddResubmitAction(nil, &conntrackTableID).Return(builder)
			},
		},
		{
			name: "RejectLocalToRemoteFlexibleIPAMSrc",
			args: args{
				rejectType:        RejectLocalToRemote,
				nodeType:          config.K8sNode,
				isFlexibleIPAMSrc: true,
				isFlexibleIPAMDst: false,
				ctZone:            1,
			},
			prepareFunc: func(builder *mocks.MockPacketOutBuilder) {
				builder.EXPECT().AddLoadRegMark(openflow.CustomReasonRejectRegMark).Return(builder)
				builder.EXPECT().AddLoadRegMark(openflow.AntreaFlexibleIPAMRegMark).Return(builder)
				builder.EXPECT().AddLoadRegMark(binding.NewRegMark(openflow.CtZoneField, 1)).Return(builder)
				builder.EXPECT().AddResubmitAction(nil, &l3ForwardingTableID).Return(builder)
			},
		},
		{
			name: "RejectLocalToRemoteFlexibleIPAMSrc",
			args: args{
				rejectType:        RejectLocalToRemote,
				nodeType:          config.K8sNode,
				isFlexibleIPAMSrc: false,
				isFlexibleIPAMDst: false,
				ctZone:            1,
			},
			prepareFunc: func(builder *mocks.MockPacketOutBuilder) {
				builder.EXPECT().AddLoadRegMark(openflow.CustomReasonRejectRegMark).Return(builder)
				builder.EXPECT().AddLoadRegMark(binding.NewRegMark(openflow.CtZoneField, 1)).Return(builder)
				builder.EXPECT().AddResubmitAction(nil, &l3ForwardingTableID).Return(builder)
			},
		},
		{
			name: "RejectServiceRemoteToLocalFlexibleIPAMDst",
			args: args{
				rejectType:        RejectServiceRemoteToLocal,
				nodeType:          config.K8sNode,
				isFlexibleIPAMSrc: false,
				isFlexibleIPAMDst: true,
				ctZone:            1,
			},
			prepareFunc: func(builder *mocks.MockPacketOutBuilder) {
				builder.EXPECT().AddLoadRegMark(openflow.CustomReasonRejectRegMark).Return(builder)
				builder.EXPECT().AddLoadRegMark(binding.NewRegMark(openflow.CtZoneField, 1)).Return(builder)
				builder.EXPECT().AddResubmitAction(nil, &conntrackTableID).Return(builder)
			},
		},
		{
			name: "Default",
			args: args{
				rejectType:        RejectServiceRemoteToLocal,
				nodeType:          config.K8sNode,
				isFlexibleIPAMSrc: false,
				isFlexibleIPAMDst: false,
				ctZone:            0,
			},
			prepareFunc: func(builder *mocks.MockPacketOutBuilder) {
				builder.EXPECT().AddLoadRegMark(openflow.CustomReasonRejectRegMark).Return(builder)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := mocks.NewMockPacketOutBuilder(ctrl)
			tt.prepareFunc(builder)
			getRejectPacketOutMutateFunc(tt.args.rejectType, tt.args.nodeType, tt.args.isFlexibleIPAMSrc, tt.args.isFlexibleIPAMDst, tt.args.ctZone)(builder)
		})
	}
}
