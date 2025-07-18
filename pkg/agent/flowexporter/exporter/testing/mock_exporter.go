// Copyright 2025 Antrea Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

// Code generated by MockGen. DO NOT EDIT.
// Source: antrea.io/antrea/pkg/agent/flowexporter/exporter (interfaces: Interface)
//
// Generated by this command:
//
//	mockgen -copyright_file hack/boilerplate/license_header.raw.txt -destination pkg/agent/flowexporter/exporter/testing/mock_exporter.go -package testing antrea.io/antrea/pkg/agent/flowexporter/exporter Interface
//

// Package testing is a generated GoMock package.
package testing

import (
	reflect "reflect"

	connection "antrea.io/antrea/pkg/agent/flowexporter/connection"
	exporter "antrea.io/antrea/pkg/agent/flowexporter/exporter"
	gomock "go.uber.org/mock/gomock"
)

// MockInterface is a mock of Interface interface.
type MockInterface struct {
	ctrl     *gomock.Controller
	recorder *MockInterfaceMockRecorder
	isgomock struct{}
}

// MockInterfaceMockRecorder is the mock recorder for MockInterface.
type MockInterfaceMockRecorder struct {
	mock *MockInterface
}

// NewMockInterface creates a new mock instance.
func NewMockInterface(ctrl *gomock.Controller) *MockInterface {
	mock := &MockInterface{ctrl: ctrl}
	mock.recorder = &MockInterfaceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockInterface) EXPECT() *MockInterfaceMockRecorder {
	return m.recorder
}

// CloseConnToCollector mocks base method.
func (m *MockInterface) CloseConnToCollector() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "CloseConnToCollector")
}

// CloseConnToCollector indicates an expected call of CloseConnToCollector.
func (mr *MockInterfaceMockRecorder) CloseConnToCollector() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CloseConnToCollector", reflect.TypeOf((*MockInterface)(nil).CloseConnToCollector))
}

// ConnectToCollector mocks base method.
func (m *MockInterface) ConnectToCollector(addr string, tlsConfig *exporter.TLSConfig) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ConnectToCollector", addr, tlsConfig)
	ret0, _ := ret[0].(error)
	return ret0
}

// ConnectToCollector indicates an expected call of ConnectToCollector.
func (mr *MockInterfaceMockRecorder) ConnectToCollector(addr, tlsConfig any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ConnectToCollector", reflect.TypeOf((*MockInterface)(nil).ConnectToCollector), addr, tlsConfig)
}

// Export mocks base method.
func (m *MockInterface) Export(conn *connection.Connection) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Export", conn)
	ret0, _ := ret[0].(error)
	return ret0
}

// Export indicates an expected call of Export.
func (mr *MockInterfaceMockRecorder) Export(conn any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Export", reflect.TypeOf((*MockInterface)(nil).Export), conn)
}
