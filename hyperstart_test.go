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

package virtcontainers

import (
	"encoding/binary"
	"encoding/json"
	"math/rand"
	"net"
	"reflect"
	"testing"

	"github.com/01org/cc-oci-runtime/tests/mock"
)

func connectHyperstart(t *testing.T) (*mock.Hyperstart, net.Conn, net.Conn, error) {
	h := mock.NewHyperstart(t)

	h.Start()

	ctlSock, ttySock := h.GetSocketPaths()

	cCtl, err := net.Dial("unix", ctlSock)
	if err != nil {
		h.Stop()
		return nil, nil, nil, err
	}

	cTty, err := net.Dial("unix", ttySock)
	if err != nil {
		cCtl.Close()
		h.Stop()
		return nil, nil, nil, err
	}

	return h, cCtl, cTty, nil
}

func disconnectHyperstart(cCtl, cTty net.Conn) {
	cTty.Close()
	cCtl.Close()
}

func testHyperstartSendCmd(t *testing.T, cmdID uint32, payload interface{}) {
	h, cCtl, cTty, err := connectHyperstart(t)
	if err != nil {
		t.Fatal()
	}

	defer h.Stop()
	defer disconnectHyperstart(cCtl, cTty)

	err = sendCmd(cCtl, cmdID, payload)
	if err != nil {
		t.Fatal()
	}
}

var cmdList = []uint32{
	getVersion,
	startPod,
	getPod,
	restartContainer,
	execCommand,
	cmdFinished,
	ready,
	ack,
	hyperError,
	winSize,
	ping,
	podFinished,
	next,
	newContainer,
	killContainer,
	onlineCPUMem,
	setupInterface,
	setupRoute,
}

func TestHyperstartSendCmd(t *testing.T) {
	for _, cmd := range cmdList {
		testHyperstartSendCmd(t, cmd, nil)
	}
}

func testHyperstartSendSeq(t *testing.T, seq uint64, payload string) {
	h, cCtl, cTty, err := connectHyperstart(t)
	if err != nil {
		t.Fatal()
	}

	defer h.Stop()
	defer disconnectHyperstart(cCtl, cTty)

	err = sendSeq(cTty, seq, payload)
	if err != nil {
		t.Fatal()
	}

	buf := make([]byte, 512)
	n, recvSeq := h.ReadIo(buf)

	recvPayload := string(buf[ttyHdrSize:n])
	if recvSeq != seq || recvPayload != payload {
		t.Fatal()
	}
}

func TestHyperstartSendSeqHello(t *testing.T) {
	testHyperstartSendSeq(t, uint64(rand.Int63()), "hello")
}

func testHyperstartWaitForReply(t *testing.T, cmdID uint32, payload interface{}) {
	var payloadStr string

	h, cCtl, cTty, err := connectHyperstart(t)
	if err != nil {
		t.Fatal()
	}

	defer h.Stop()
	defer disconnectHyperstart(cCtl, cTty)

	if payload != nil {
		jsonOut, err := json.Marshal(payload)
		if err != nil {
			t.Fatal()
		}

		payloadStr = string(jsonOut)
	} else {
		payloadStr = ""
	}

	payloadLen := make([]byte, ctlHdrSize-ctlHdrLenOffset)
	length := len(payloadStr) + ctlHdrSize
	binary.BigEndian.PutUint32(payloadLen, uint32(length))

	cmdStr, err := uint64ToNBytesString(uint64(cmdID), ctlHdrLenOffset)
	if err != nil {
		t.Fatal()
	}

	frame := frame{
		cmd:        cmdStr,
		payloadLen: string(payloadLen),
		payload:    payloadStr,
	}

	err = send(cCtl, frame)
	if err != nil {
		t.Fatal()
	}

	err = waitForReply(cCtl, ack)
	if err != nil {
		t.Fatal()
	}
}

func TestHyperstartWaitForReplyToPingCmd(t *testing.T) {
	testHyperstartWaitForReply(t, ping, nil)
}

func testHyperstartFormatFrame(t *testing.T, cmd uint64, payload interface{}, chType chType, expected frame) {
	frame, err := formatFrame(cmd, payload, chType)
	if err != nil {
		t.Fatal()
	}

	if reflect.DeepEqual(frame, expected) == false {
		t.Fatal()
	}
}

func TestHyperstartFormatFrameCtl(t *testing.T) {
	cmd := ping
	payload := "testPayload"

	cmdStr, err := uint64ToNBytesString(uint64(cmd), 4)
	if err != nil {
		t.Fatal()
	}

	payloadLenStr, err := uint64ToNBytesString(uint64(19), 4)
	if err != nil {
		t.Fatal()
	}

	expected := frame{
		cmd:        cmdStr,
		payloadLen: payloadLenStr,
		payload:    payload,
	}

	testHyperstartFormatFrame(t, uint64(cmd), payload, ctlType, expected)
}

func TestHyperstartFormatFrameTty(t *testing.T) {
	seq := 1
	payload := "testPayload"

	seqStr, err := uint64ToNBytesString(uint64(seq), 8)
	if err != nil {
		t.Fatal()
	}

	payloadLenStr, err := uint64ToNBytesString(uint64(23), 4)
	if err != nil {
		t.Fatal()
	}

	expected := frame{
		cmd:        seqStr,
		payloadLen: payloadLenStr,
		payload:    payload,
	}

	testHyperstartFormatFrame(t, uint64(seq), payload, ttyType, expected)
}
