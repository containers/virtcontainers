//
// Copyright (c) 2016 Intel Corporation
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

package hyperstart

import (
	"math"
	"net"
	"reflect"
	"testing"
	"time"

	hyper "github.com/containers/virtcontainers/pkg/hyperstart/api"
	"github.com/containers/virtcontainers/pkg/hyperstart/mock"
)

const (
	testSockType = "unix"
	testSequence = uint64(100)
	testMessage  = "test_message"
)

func connectHyperstartNoMulticast(h *Hyperstart) error {
	var err error

	h.ctl, err = net.Dial(h.sockType, h.ctlSerial)
	if err != nil {
		return err
	}
	h.ctlState.open()

	h.io, err = net.Dial(h.sockType, h.ioSerial)
	if err != nil {
		h.ctl.Close()
		return err
	}
	h.ioState.open()

	return nil
}

func connectHyperstart(h *Hyperstart) error {
	return h.OpenSockets()
}

func disconnectHyperstart(h *Hyperstart) {
	h.CloseSockets()
}

func connectMockHyperstart(t *testing.T, multiCast bool) (*mock.Hyperstart, *Hyperstart, error) {
	mockHyper := mock.NewHyperstart(t)

	mockHyper.Start()

	ctlSock, ioSock := mockHyper.GetSocketPaths()

	h := &Hyperstart{
		ctlSerial: ctlSock,
		ioSerial:  ioSock,
		sockType:  testSockType,
	}

	var err error
	if multiCast {
		err = connectHyperstart(h)
	} else {
		err = connectHyperstartNoMulticast(h)
	}
	if err != nil {
		mockHyper.Stop()
		return nil, nil, err
	}

	return mockHyper, h, nil
}

func TestNewHyperstart(t *testing.T) {
	ctlSock := "/tmp/test_hyper.sock"
	ioSock := "/tmp/test_tty.sock"
	sockType := "test_unix"

	expectedOut := &Hyperstart{
		ctlSerial: ctlSock,
		ioSerial:  ioSock,
		sockType:  sockType,
	}

	h := NewHyperstart(ctlSock, ioSock, sockType)

	if reflect.DeepEqual(h, expectedOut) == false {
		t.Fatal()
	}
}

func TestOpenSockets(t *testing.T) {
	mockHyper := mock.NewHyperstart(t)

	mockHyper.Start()
	defer mockHyper.Stop()

	ctlSock, ioSock := mockHyper.GetSocketPaths()

	h := &Hyperstart{
		ctlSerial: ctlSock,
		ioSerial:  ioSock,
		sockType:  testSockType,
	}

	err := h.OpenSockets()
	if err != nil {
		t.Fatal()
	}

	disconnectHyperstart(h)
}

func TestCloseSockets(t *testing.T) {
	mockHyper, h, err := connectMockHyperstart(t, true)
	if err != nil {
		t.Fatal()
	}
	defer mockHyper.Stop()

	err = h.CloseSockets()
	if err != nil {
		t.Fatal()
	}
}

func TestSetDeadline(t *testing.T) {
	mockHyper, h, err := connectMockHyperstart(t, false)
	if err != nil {
		t.Fatal()
	}
	defer mockHyper.Stop()
	defer disconnectHyperstart(h)

	timeoutDuration := 1 * time.Second

	err = h.SetDeadline(time.Now().Add(timeoutDuration))
	if err != nil {
		t.Fatal()
	}

	mockHyper.SendMessage(hyper.Ready, []byte{})

	buf := make([]byte, 512)
	_, err = h.ctl.Read(buf)
	if err != nil {
		t.Fatal()
	}

	err = h.SetDeadline(time.Now().Add(timeoutDuration))
	if err != nil {
		t.Fatal()
	}

	time.Sleep(timeoutDuration)

	_, err = h.ctl.Read(buf)
	netErr, ok := err.(net.Error)
	if ok && netErr.Timeout() == false {
		t.Fatal()
	}
}

func TestIsStartedFalse(t *testing.T) {
	h := &Hyperstart{}

	if h.IsStarted() == true {
		t.Fatal()
	}
}

func TestIsStartedTrue(t *testing.T) {
	mockHyper, h, err := connectMockHyperstart(t, true)
	if err != nil {
		t.Fatal()
	}
	defer mockHyper.Stop()
	defer disconnectHyperstart(h)

	if h.IsStarted() == false {
		t.Fatal()
	}
}

func testFormatMessage(t *testing.T, payload interface{}, expected []byte) {
	res, err := FormatMessage(payload)
	if err != nil {
		t.Fatal()
	}

	if reflect.DeepEqual(res, expected) == false {
		t.Fatal()
	}
}

func TestFormatMessageFromString(t *testing.T) {
	payload := testMessage
	expectedOut := []byte(payload)

	testFormatMessage(t, payload, expectedOut)
}

type TestStruct struct {
	FieldString string `json:"fieldString"`
	FieldInt    int    `json:"fieldInt"`
}

func TestFormatMessageFromStruct(t *testing.T) {
	payload := TestStruct{
		FieldString: "test_string",
		FieldInt:    100,
	}

	expectedOut := []byte("{\"fieldString\":\"test_string\",\"fieldInt\":100}")

	testFormatMessage(t, payload, expectedOut)
}

func TestReadCtlMessage(t *testing.T) {
	mockHyper, h, err := connectMockHyperstart(t, false)
	if err != nil {
		t.Fatal()
	}
	defer mockHyper.Stop()
	defer disconnectHyperstart(h)

	expected := &hyper.DecodedMessage{
		Code:    hyper.Ready,
		Message: []byte{},
	}

	mockHyper.SendMessage(int(expected.Code), expected.Message)

	reply, err := ReadCtlMessage(h.ctl)
	if err != nil {
		t.Fatal()
	}

	if reflect.DeepEqual(reply, expected) == false {
		t.Fatal()
	}
}

func TestWriteCtlMessage(t *testing.T) {
	mockHyper, h, err := connectMockHyperstart(t, false)
	if err != nil {
		t.Fatal()
	}
	defer mockHyper.Stop()
	defer disconnectHyperstart(h)

	msg := hyper.DecodedMessage{
		Code:    hyper.Ping,
		Message: []byte{},
	}

	err = h.WriteCtlMessage(h.ctl, &msg)
	if err != nil {
		t.Fatal()
	}

	for {
		reply, err := ReadCtlMessage(h.ctl)
		if err != nil {
			t.Fatal()
		}

		if reply.Code == hyper.Next {
			continue
		}

		err = h.checkReturnedCode(reply.Code, hyper.Ack)
		if err != nil {
			t.Fatal()
		}

		break
	}

	msgs := mockHyper.GetLastMessages()
	if msgs == nil {
		t.Fatal()
	}

	if msgs[0].Code != msg.Code || string(msgs[0].Message) != string(msg.Message) {
		t.Fatal()
	}
}

func TestReadIoMessage(t *testing.T) {
	mockHyper, h, err := connectMockHyperstart(t, true)
	if err != nil {
		t.Fatal()
	}
	defer mockHyper.Stop()
	defer disconnectHyperstart(h)

	mockHyper.SendIo(testSequence, []byte(testMessage))

	msg, err := h.ReadIoMessage()
	if err != nil {
		t.Fatal()
	}

	if msg.Session != testSequence || string(msg.Message) != testMessage {
		t.Fatal()
	}
}

func TestReadIoMessageWithConn(t *testing.T) {
	mockHyper, h, err := connectMockHyperstart(t, true)
	if err != nil {
		t.Fatal()
	}
	defer mockHyper.Stop()
	defer disconnectHyperstart(h)

	mockHyper.SendIo(testSequence, []byte(testMessage))

	msg, err := ReadIoMessageWithConn(h.io)
	if err != nil {
		t.Fatal()
	}

	if msg.Session != testSequence || string(msg.Message) != testMessage {
		t.Fatal()
	}
}

func TestSendIoMessage(t *testing.T) {
	mockHyper, h, err := connectMockHyperstart(t, true)
	if err != nil {
		t.Fatal()
	}
	defer mockHyper.Stop()
	defer disconnectHyperstart(h)

	msg := &hyper.TtyMessage{
		Session: testSequence,
		Message: []byte(testMessage),
	}

	err = h.SendIoMessage(msg)
	if err != nil {
		t.Fatal()
	}

	buf := make([]byte, 512)
	n, seqRecv := mockHyper.ReadIo(buf)

	if seqRecv != testSequence || string(buf[ttyHdrSize:n]) != testMessage {
		t.Fatal()
	}
}

func TestSendIoMessageWithConn(t *testing.T) {
	mockHyper, h, err := connectMockHyperstart(t, true)
	if err != nil {
		t.Fatal()
	}
	defer mockHyper.Stop()
	defer disconnectHyperstart(h)

	msg := &hyper.TtyMessage{
		Session: testSequence,
		Message: []byte(testMessage),
	}

	err = SendIoMessageWithConn(h.io, msg)
	if err != nil {
		t.Fatal()
	}

	buf := make([]byte, 512)
	n, seqRecv := mockHyper.ReadIo(buf)

	if seqRecv != testSequence || string(buf[ttyHdrSize:n]) != testMessage {
		t.Fatal()
	}
}

func testCodeFromCmd(t *testing.T, cmd string, expected uint32) {
	code, err := codeFromCmd(cmd)
	if err != nil || code != expected {
		t.Fatal()
	}
}

func TestCodeFromCmdVersion(t *testing.T) {
	testCodeFromCmd(t, Version, hyper.Version)
}

func TestCodeFromCmdStartPod(t *testing.T) {
	testCodeFromCmd(t, StartPod, hyper.StartPod)
}

func TestCodeFromCmdDestroyPod(t *testing.T) {
	testCodeFromCmd(t, DestroyPod, hyper.DestroyPod)
}

func TestCodeFromCmdExecCmd(t *testing.T) {
	testCodeFromCmd(t, ExecCmd, hyper.ExecCmd)
}

func TestCodeFromCmdReady(t *testing.T) {
	testCodeFromCmd(t, Ready, hyper.Ready)
}

func TestCodeFromCmdAck(t *testing.T) {
	testCodeFromCmd(t, Ack, hyper.Ack)
}

func TestCodeFromCmdError(t *testing.T) {
	testCodeFromCmd(t, Error, hyper.Error)
}

func TestCodeFromCmdWinSize(t *testing.T) {
	testCodeFromCmd(t, WinSize, hyper.Winsize)
}

func TestCodeFromCmdPing(t *testing.T) {
	testCodeFromCmd(t, Ping, hyper.Ping)
}

func TestCodeFromCmdNext(t *testing.T) {
	testCodeFromCmd(t, Next, hyper.Next)
}

func TestCodeFromCmdWriteFile(t *testing.T) {
	testCodeFromCmd(t, WriteFile, hyper.WriteFile)
}

func TestCodeFromCmdReadFile(t *testing.T) {
	testCodeFromCmd(t, ReadFile, hyper.ReadFile)
}

func TestCodeFromCmdNewContainer(t *testing.T) {
	testCodeFromCmd(t, NewContainer, hyper.NewContainer)
}

func TestCodeFromCmdKillContainer(t *testing.T) {
	testCodeFromCmd(t, KillContainer, hyper.KillContainer)
}

func TestCodeFromCmdOnlineCPUMem(t *testing.T) {
	testCodeFromCmd(t, OnlineCPUMem, hyper.OnlineCPUMem)
}

func TestCodeFromCmdSetupInterface(t *testing.T) {
	testCodeFromCmd(t, SetupInterface, hyper.SetupInterface)
}

func TestCodeFromCmdSetupRoute(t *testing.T) {
	testCodeFromCmd(t, SetupRoute, hyper.SetupRoute)
}

func TestCodeFromCmdRemoveContainer(t *testing.T) {
	testCodeFromCmd(t, RemoveContainer, hyper.RemoveContainer)
}

func TestCodeFromCmdUnknown(t *testing.T) {
	code, err := codeFromCmd("unknown")
	if err == nil || code != math.MaxUint32 {
		t.Fatal()
	}
}

func testCheckReturnedCode(t *testing.T, code, refCode uint32) {
	h := &Hyperstart{}

	err := h.checkReturnedCode(code, refCode)
	if err != nil {
		t.Fatal()
	}
}

func TestCheckReturnedCodeList(t *testing.T) {
	for _, code := range codeList {
		testCheckReturnedCode(t, code, code)
	}
}

func testCheckReturnedCodeFailure(t *testing.T, code, refCode uint32) {
	h := &Hyperstart{}

	err := h.checkReturnedCode(code, refCode)
	if err == nil {
		t.Fatal()
	}
}

func TestCheckReturnedCodeListWrong(t *testing.T) {
	for _, code := range codeList {
		if code != hyper.Ready {
			testCheckReturnedCodeFailure(t, code, hyper.Ready)
		} else {
			testCheckReturnedCodeFailure(t, code, hyper.Ping)
		}
	}
}

func TestWaitForReady(t *testing.T) {
	mockHyper, h, err := connectMockHyperstart(t, true)
	if err != nil {
		t.Fatal()
	}
	defer mockHyper.Stop()
	defer disconnectHyperstart(h)

	mockHyper.SendMessage(int(hyper.Ready), []byte{})

	err = h.WaitForReady()
	if err != nil {
		t.Fatal()
	}
}

func TestWaitForReadyError(t *testing.T) {
	mockHyper, h, err := connectMockHyperstart(t, true)
	if err != nil {
		t.Fatal()
	}
	defer mockHyper.Stop()
	defer disconnectHyperstart(h)

	mockHyper.SendMessage(int(hyper.Error), []byte{})

	err = h.WaitForReady()
	if err == nil {
		t.Fatal()
	}
}

var cmdList = []string{
	Version,
	StartPod,
	DestroyPod,
	ExecCmd,
	Ready,
	Ack,
	Error,
	WinSize,
	Ping,
	Next,
	NewContainer,
	KillContainer,
	OnlineCPUMem,
	SetupInterface,
	SetupRoute,
}

func testSendCtlMessage(t *testing.T, cmd string) {
	mockHyper, h, err := connectMockHyperstart(t, true)
	if err != nil {
		t.Fatal()
	}
	defer mockHyper.Stop()
	defer disconnectHyperstart(h)

	msg, err := h.SendCtlMessage(cmd, []byte{})
	if err != nil {
		t.Fatal()
	}

	if msg.Code != hyper.Ack {
		t.Fatal()
	}
}

func TestSendCtlMessage(t *testing.T) {
	for _, cmd := range cmdList {
		testSendCtlMessage(t, cmd)
	}
}
