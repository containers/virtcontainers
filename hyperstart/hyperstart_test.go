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

	"github.com/containers/virtcontainers/hyperstart/mock"
	hyper "github.com/hyperhq/runv/hyperstart/api/json"
)

const (
	testSockType = "unix"
	testSequence = uint64(100)
	testMessage  = "test_message"
)

func connectHyperstart(ctlSock, ioSock, sockType string) (net.Conn, net.Conn, error) {
	var err error
	var cCtl net.Conn
	var cIo net.Conn

	cCtl, err = net.Dial(sockType, ctlSock)
	if err != nil {
		return nil, nil, err
	}

	cIo, err = net.Dial(sockType, ioSock)
	if err != nil {
		cCtl.Close()
		return nil, nil, err
	}

	return cCtl, cIo, nil
}

func connectMockHyperstart(t *testing.T) (*mock.Hyperstart, *Hyperstart, error) {
	mockHyper := mock.NewHyperstart(t)

	mockHyper.Start()

	ctlSock, ioSock := mockHyper.GetSocketPaths()

	cCtl, cIo, err := connectHyperstart(ctlSock, ioSock, testSockType)
	if err != nil {
		mockHyper.Stop()
		return nil, nil, err
	}

	h := &Hyperstart{
		ctlSerial: ctlSock,
		ioSerial:  ioSock,
		sockType:  testSockType,
		ctl:       cCtl,
		io:        cIo,
	}

	return mockHyper, h, nil
}

func disconnectHyperstart(cCtl, cIo net.Conn) {
	if cCtl != nil {
		cCtl.Close()
		cCtl = nil
	}

	if cIo != nil {
		cIo.Close()
		cIo = nil
	}
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

	disconnectHyperstart(h.ctl, h.io)
}

func TestCloseSockets(t *testing.T) {
	mockHyper, h, err := connectMockHyperstart(t)
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
	mockHyper, h, err := connectMockHyperstart(t)
	if err != nil {
		t.Fatal()
	}
	defer mockHyper.Stop()
	defer disconnectHyperstart(h.ctl, h.io)

	timeoutDuration := 1 * time.Second

	err = h.SetDeadline(time.Now().Add(timeoutDuration))
	if err != nil {
		t.Fatal()
	}

	mockHyper.SendMessage(hyper.INIT_READY, []byte{})

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
	mockHyper, h, err := connectMockHyperstart(t)
	if err != nil {
		t.Fatal()
	}
	defer mockHyper.Stop()
	defer disconnectHyperstart(h.ctl, h.io)

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
	mockHyper, h, err := connectMockHyperstart(t)
	if err != nil {
		t.Fatal()
	}
	defer mockHyper.Stop()
	defer disconnectHyperstart(h.ctl, h.io)

	expected := &hyper.DecodedMessage{
		Code:    hyper.INIT_READY,
		Message: []byte{},
	}

	mockHyper.SendMessage(int(expected.Code), expected.Message)

	reply, err := h.readCtlMessage()
	if err != nil {
		t.Fatal()
	}

	if reflect.DeepEqual(reply, expected) == false {
		t.Fatal()
	}
}

func TestWriteCtlMessage(t *testing.T) {
	mockHyper, h, err := connectMockHyperstart(t)
	if err != nil {
		t.Fatal()
	}
	defer mockHyper.Stop()
	defer disconnectHyperstart(h.ctl, h.io)

	msg := hyper.DecodedMessage{
		Code:    hyper.INIT_PING,
		Message: []byte{},
	}

	err = h.writeCtlMessage(&msg)
	if err != nil {
		t.Fatal()
	}

	_, err = h.expectReadingCmd(hyper.INIT_ACK)
	if err != nil {
		t.Fatal()
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
	mockHyper, h, err := connectMockHyperstart(t)
	if err != nil {
		t.Fatal()
	}
	defer mockHyper.Stop()
	defer disconnectHyperstart(h.ctl, h.io)

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
	mockHyper, h, err := connectMockHyperstart(t)
	if err != nil {
		t.Fatal()
	}
	defer mockHyper.Stop()
	defer disconnectHyperstart(h.ctl, h.io)

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
	mockHyper, h, err := connectMockHyperstart(t)
	if err != nil {
		t.Fatal()
	}
	defer mockHyper.Stop()
	defer disconnectHyperstart(h.ctl, h.io)

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
	mockHyper, h, err := connectMockHyperstart(t)
	if err != nil {
		t.Fatal()
	}
	defer mockHyper.Stop()
	defer disconnectHyperstart(h.ctl, h.io)

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
	testCodeFromCmd(t, Version, hyper.INIT_VERSION)
}

func TestCodeFromCmdStartPod(t *testing.T) {
	testCodeFromCmd(t, StartPod, hyper.INIT_STARTPOD)
}

func TestCodeFromCmdGetPod(t *testing.T) {
	testCodeFromCmd(t, GetPod, hyper.INIT_GETPOD)
}

func TestCodeFromCmdDestroyPod(t *testing.T) {
	testCodeFromCmd(t, DestroyPod, hyper.INIT_DESTROYPOD)
}

func TestCodeFromCmdRestartContainer(t *testing.T) {
	testCodeFromCmd(t, RestartContainer, hyper.INIT_RESTARTCONTAINER)
}

func TestCodeFromCmdExecCmd(t *testing.T) {
	testCodeFromCmd(t, ExecCmd, hyper.INIT_EXECCMD)
}

func TestCodeFromCmdFinishCmd(t *testing.T) {
	testCodeFromCmd(t, FinishCmd, hyper.INIT_FINISHCMD)
}

func TestCodeFromCmdReady(t *testing.T) {
	testCodeFromCmd(t, Ready, hyper.INIT_READY)
}

func TestCodeFromCmdAck(t *testing.T) {
	testCodeFromCmd(t, Ack, hyper.INIT_ACK)
}

func TestCodeFromCmdError(t *testing.T) {
	testCodeFromCmd(t, Error, hyper.INIT_ERROR)
}

func TestCodeFromCmdWinSize(t *testing.T) {
	testCodeFromCmd(t, WinSize, hyper.INIT_WINSIZE)
}

func TestCodeFromCmdPing(t *testing.T) {
	testCodeFromCmd(t, Ping, hyper.INIT_PING)
}

func TestCodeFromCmdFinishPod(t *testing.T) {
	testCodeFromCmd(t, FinishPod, hyper.INIT_FINISHPOD)
}

func TestCodeFromCmdNext(t *testing.T) {
	testCodeFromCmd(t, Next, hyper.INIT_NEXT)
}

func TestCodeFromCmdWriteFile(t *testing.T) {
	testCodeFromCmd(t, WriteFile, hyper.INIT_WRITEFILE)
}

func TestCodeFromCmdReadFile(t *testing.T) {
	testCodeFromCmd(t, ReadFile, hyper.INIT_READFILE)
}

func TestCodeFromCmdNewContainer(t *testing.T) {
	testCodeFromCmd(t, NewContainer, hyper.INIT_NEWCONTAINER)
}

func TestCodeFromCmdKillContainer(t *testing.T) {
	testCodeFromCmd(t, KillContainer, hyper.INIT_KILLCONTAINER)
}

func TestCodeFromCmdOnlineCPUMem(t *testing.T) {
	testCodeFromCmd(t, OnlineCPUMem, hyper.INIT_ONLINECPUMEM)
}

func TestCodeFromCmdSetupInterface(t *testing.T) {
	testCodeFromCmd(t, SetupInterface, hyper.INIT_SETUPINTERFACE)
}

func TestCodeFromCmdSetupRoute(t *testing.T) {
	testCodeFromCmd(t, SetupRoute, hyper.INIT_SETUPROUTE)
}

func TestCodeFromCmdUnknown(t *testing.T) {
	code, err := codeFromCmd("unknown")
	if err == nil || code != math.MaxUint32 {
		t.Fatal()
	}
}

func testExpectReadingCmd(t *testing.T, code uint32) {
	mockHyper, h, err := connectMockHyperstart(t)
	if err != nil {
		t.Fatal()
	}
	defer mockHyper.Stop()
	defer disconnectHyperstart(h.ctl, h.io)

	mockHyper.SendMessage(int(hyper.INIT_READY), []byte{})

	mockHyper.SendMessage(int(code), []byte{})

	msg, err := h.expectReadingCmd(code)
	if err != nil {
		t.Fatal()
	}

	if msg.Code != code || string(msg.Message) != "" {
		t.Fatal()
	}
}

func TestExpectReadingCmdList(t *testing.T) {
	for _, code := range codeList {
		testExpectReadingCmd(t, code)
	}
}

func testExpectReadingCmdWrong(t *testing.T, code uint32) {
	mockHyper, h, err := connectMockHyperstart(t)
	if err != nil {
		t.Fatal()
	}
	defer mockHyper.Stop()
	defer disconnectHyperstart(h.ctl, h.io)

	if code == hyper.INIT_ERROR {
		mockHyper.SendMessage(int(hyper.INIT_ACK), []byte{})
	} else {
		mockHyper.SendMessage(int(hyper.INIT_ERROR), []byte{})
	}

	msg, err := h.expectReadingCmd(code)
	if err == nil || msg != nil {
		t.Fatal()
	}
}

func TestExpectReadingCmdListWrong(t *testing.T) {
	for _, code := range codeList {
		testExpectReadingCmdWrong(t, code)
	}
}

func TestWaitForReady(t *testing.T) {
	mockHyper, h, err := connectMockHyperstart(t)
	if err != nil {
		t.Fatal()
	}
	defer mockHyper.Stop()
	defer disconnectHyperstart(h.ctl, h.io)

	mockHyper.SendMessage(int(hyper.INIT_READY), []byte{})

	err = h.WaitForReady()
	if err != nil {
		t.Fatal()
	}
}

func TestWaitForReadyError(t *testing.T) {
	mockHyper, h, err := connectMockHyperstart(t)
	if err != nil {
		t.Fatal()
	}
	defer mockHyper.Stop()
	defer disconnectHyperstart(h.ctl, h.io)

	mockHyper.SendMessage(int(hyper.INIT_ERROR), []byte{})

	err = h.WaitForReady()
	if err == nil {
		t.Fatal()
	}
}

var cmdList = []string{
	Version,
	StartPod,
	GetPod,
	DestroyPod,
	RestartContainer,
	ExecCmd,
	FinishCmd,
	Ready,
	Ack,
	Error,
	WinSize,
	Ping,
	FinishPod,
	Next,
	NewContainer,
	KillContainer,
	OnlineCPUMem,
	SetupInterface,
	SetupRoute,
}

func testSendCtlMessage(t *testing.T, cmd string) {
	mockHyper, h, err := connectMockHyperstart(t)
	if err != nil {
		t.Fatal()
	}
	defer mockHyper.Stop()
	defer disconnectHyperstart(h.ctl, h.io)

	msg, err := h.SendCtlMessage(cmd, []byte{})
	if err != nil {
		t.Fatal()
	}

	if cmd != DestroyPod && msg.Code != hyper.INIT_ACK {
		t.Fatal()
	}
}

func TestSendCtlMessage(t *testing.T) {
	for _, cmd := range cmdList {
		testSendCtlMessage(t, cmd)
	}
}
