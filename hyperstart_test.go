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

func testHyperstartSendCmd(t *testing.T, cmdID string, payload interface{}) {
	h, cCtl, cTty, err := connectHyperstart(t)
	if err != nil {
		t.Fail()
		return
	}

	defer h.Stop()
	defer disconnectHyperstart(cCtl, cTty)

	err = sendCmd(cCtl, cmdID, payload)
	if err != nil {
		t.Fail()
	}
}

func TestHyperstartSendCmdGetVersion(t *testing.T) {
	testHyperstartSendCmd(t, getVersion, nil)
}

func TestHyperstartSendCmdStartPod(t *testing.T) {
	testHyperstartSendCmd(t, startPod, nil)
}

func TestHyperstartSendCmdGetPod(t *testing.T) {
	testHyperstartSendCmd(t, getPod, nil)
}

/*
func TestHyperstartSendCmdDestroyPod(t *testing.T) {
	testHyperstartSendCmd(t, destroyPod, nil)
}
*/

func TestHyperstartSendCmdRestartContainer(t *testing.T) {
	testHyperstartSendCmd(t, restartContainer, nil)
}

func TestHyperstartSendCmdExecCommand(t *testing.T) {
	testHyperstartSendCmd(t, execCommand, nil)
}

func TestHyperstartSendCmdCmdFinished(t *testing.T) {
	testHyperstartSendCmd(t, cmdFinished, nil)
}

func TestHyperstartSendCmdReady(t *testing.T) {
	testHyperstartSendCmd(t, ready, nil)
}

func TestHyperstartSendCmdAck(t *testing.T) {
	testHyperstartSendCmd(t, ack, nil)
}

func TestHyperstartSendCmdHyperError(t *testing.T) {
	testHyperstartSendCmd(t, hyperError, nil)
}

func TestHyperstartSendCmdWinSize(t *testing.T) {
	testHyperstartSendCmd(t, winSize, nil)
}

func TestHyperstartSendCmdPing(t *testing.T) {
	testHyperstartSendCmd(t, ping, nil)
}

func TestHyperstartSendCmdPodFinished(t *testing.T) {
	testHyperstartSendCmd(t, podFinished, nil)
}

func TestHyperstartSendCmdNext(t *testing.T) {
	testHyperstartSendCmd(t, next, nil)
}

func TestHyperstartSendCmdNewContainer(t *testing.T) {
	testHyperstartSendCmd(t, newContainer, nil)
}

func TestHyperstartSendCmdKillContainer(t *testing.T) {
	testHyperstartSendCmd(t, killContainer, nil)
}

func TestHyperstartSendCmdOnlineCPUMem(t *testing.T) {
	testHyperstartSendCmd(t, onlineCPUMem, nil)
}

func TestHyperstartSendCmdSetupInterface(t *testing.T) {
	testHyperstartSendCmd(t, setupInterface, nil)
}

func TestHyperstartSendCmdSetupRoute(t *testing.T) {
	testHyperstartSendCmd(t, setupRoute, nil)
}

func testHyperstartSendSeq(t *testing.T, seq uint64, payload string) {
	h, cCtl, cTty, err := connectHyperstart(t)
	if err != nil {
		t.Fail()
		return
	}

	defer h.Stop()
	defer disconnectHyperstart(cCtl, cTty)

	err = sendSeq(cTty, seq, payload)
	if err != nil {
		t.Fail()
		return
	}

	buf := make([]byte, 512)
	n, recvSeq := h.ReadIo(buf)

	recvPayload := string(buf[ttyHdrSize:n])
	if recvSeq != seq || recvPayload != payload {
		t.Fail()
	}
}

func TestHyperstartSendSeqHello(t *testing.T) {
	testHyperstartSendSeq(t, uint64(rand.Int63()), "hello")
}

func testHyperstartWaitForReply(t *testing.T, cmdID string, payload interface{}) {
	var payloadStr string

	h, cCtl, cTty, err := connectHyperstart(t)
	if err != nil {
		t.Fail()
		return
	}

	defer h.Stop()
	defer disconnectHyperstart(cCtl, cTty)

	if payload != nil {
		jsonOut, err := json.Marshal(payload)
		if err != nil {
			t.Fail()
			return
		}

		payloadStr = string(jsonOut)
	} else {
		payloadStr = ""
	}

	payloadLen := make([]byte, ctlHdrSize-ctlHdrLenOffset)
	length := len(payloadStr) + ctlHdrSize
	binary.BigEndian.PutUint32(payloadLen, uint32(length))

	frame := frame{
		cmd:        cmdID,
		payloadLen: string(payloadLen),
		payload:    payloadStr,
	}

	err = send(cCtl, frame)
	if err != nil {
		t.Fail()
		return
	}

	err = waitForReply(cCtl, ack)
	if err != nil {
		t.Fail()
	}
}

func TestHyperstartWaitForReplyToPingCmd(t *testing.T) {
	testHyperstartWaitForReply(t, ping, nil)
}
