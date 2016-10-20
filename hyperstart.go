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
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"time"

	"github.com/golang/glog"

	hyperJson "github.com/hyperhq/runv/hyperstart/api/json"
)

// Control command IDs
// Need to be in sync with hyperstart/src/api.h
const (
	getVersion        = "\x00\x00\x00\x00"
	startPod          = "\x00\x00\x00\x01"
	getPod            = "\x00\x00\x00\x02"
	stopPodDeprecated = "\x00\x00\x00\x03"
	destroyPod        = "\x00\x00\x00\x04"
	restartContainer  = "\x00\x00\x00\x05"
	execCommand       = "\x00\x00\x00\x06"
	cmdFinished       = "\x00\x00\x00\x07"
	ready             = "\x00\x00\x00\x08"
	ack               = "\x00\x00\x00\x09"
	hyperError        = "\x00\x00\x00\x0a"
	winSize           = "\x00\x00\x00\x0b"
	ping              = "\x00\x00\x00\x0c"
	podFinished       = "\x00\x00\x00\x0d"
	next              = "\x00\x00\x00\x0e"
	writeFile         = "\x00\x00\x00\x0f"
	readFile          = "\x00\x00\x00\x10"
	newContainer      = "\x00\x00\x00\x11"
	killContainer     = "\x00\x00\x00\x12"
	onlineCPUMem      = "\x00\x00\x00\x13"
	setupInterface    = "\x00\x00\x00\x14"
	setupRoute        = "\x00\x00\x00\x15"
	removeContainer   = "\x00\x00\x00\x16"
)

// Values related to the communication on control channel.
const (
	ctlHdrSize      = 8
	ctlHdrLenOffset = 4
)

// Values related to the communication on tty channel.
const (
	ttyHdrSize      = 12
	ttyHdrLenOffset = 8
)

// chType differentiates channels type.
type chType uint8

// List of possible values for channels type.
const (
	ctlType chType = iota
	ttyType
)

// HyperConfig is a structure storing information needed for
// hyperstart agent initialization.
type HyperConfig struct {
	SockCtlName string
	SockTtyName string
	SockCtlType string
	SockTtyType string
	Volumes     []Volume
}

// hyper is the Agent interface implementation for hyperstart.
type hyper struct {
	config     HyperConfig
	hypervisor hypervisor

	cCtl net.Conn
	cTty net.Conn
}

// frame is the structure corresponding to the frame format
// used to send and receive on different channels.
type frame struct {
	cmd        string
	payloadLen string
	payload    string
}

// ExecInfo is the structure corresponding to the format
// expected by hyperstart to execute a command on the guest.
type ExecInfo struct {
	Container string            `json:"container"`
	Process   hyperJson.Process `json:"process"`
}

func (c HyperConfig) validate() bool {
	return true
}

func send(c net.Conn, frame frame) error {
	strArray := frame.cmd + frame.payloadLen + frame.payload

	c.Write([]byte(strArray))

	return nil
}

func recv(c net.Conn, chType chType) (frame, error) {
	var frame frame
	var hdrSize int
	var hdrLenOffset int

	switch chType {
	case ctlType:
		hdrSize = ctlHdrSize
		hdrLenOffset = ctlHdrLenOffset
	case ttyType:
		hdrSize = ttyHdrSize
		hdrLenOffset = ttyHdrLenOffset
	}

	byteHdr := make([]byte, hdrSize)

	byteRead, err := c.Read(byteHdr)
	if err != nil {
		return frame, err
	}

	glog.Infof("Header received: %x\n", byteHdr)

	if byteRead != hdrSize {
		return frame, fmt.Errorf("Not enough bytes read (%d/%d)\n", byteRead, hdrSize)
	}

	frame.cmd = string(byteHdr[:hdrLenOffset])
	frame.payloadLen = string(byteHdr[hdrLenOffset:])

	payloadLen, err := strconv.ParseUint(fmt.Sprintf("%x", frame.payloadLen), 16, 0)
	if err != nil {
		return frame, err
	}

	payloadLen -= uint64(hdrSize)
	glog.Infof("Payload length: %d\n", payloadLen)

	if payloadLen == 0 {
		return frame, nil
	}

	bytePayload := make([]byte, payloadLen)

	byteRead, err = c.Read(bytePayload)
	if err != nil {
		return frame, err
	}

	glog.Infof("Payload received: %x\n", bytePayload)
	if chType == ttyType {
		glog.Infof("String formatted payload: %s\n", string(bytePayload))
	}

	if byteRead != int(payloadLen) {
		return frame, fmt.Errorf("Not enough bytes read (%d/%d)\n", byteRead, payloadLen)
	}

	frame.payload = string(bytePayload)

	return frame, nil
}

func waitForReply(c net.Conn, cmdID string) error {
	for {
		frame, err := recv(c, ctlType)
		if err != nil {
			return err
		}

		if frame.cmd == cmdID {
			break
		}

		if frame.cmd == next || frame.cmd == ready {
			continue
		}

		if frame.cmd != cmdID {
			if frame.cmd == hyperError {
				return fmt.Errorf("ERROR received from Hyperstart\n")
			}

			return fmt.Errorf("CMD ID received %x not matching expected %x\n", frame.cmd, cmdID)
		}
	}

	return nil
}

func sendCmd(c net.Conn, cmdID string, payload interface{}) error {
	var payloadStr string

	if payload != nil {
		jsonOut, err := json.Marshal(payload)
		if err != nil {
			return err
		}

		payloadStr = string(jsonOut)
	} else {
		payloadStr = ""
	}

	glog.Infof("payload: %s\n", payloadStr)
	intLen := len(payloadStr) + ctlHdrSize
	payloadLen, err := uint64ToNBytesString(uint64(intLen), 4)
	if err != nil {
		return err
	}
	glog.Infof("payload len: %x\n", payloadLen)

	frame := frame{
		cmd:        cmdID,
		payloadLen: payloadLen,
		payload:    payloadStr,
	}

	err = send(c, frame)
	if err != nil {
		return err
	}

	if cmdID == destroyPod {
		return nil
	}

	err = waitForReply(c, ack)
	if err != nil {
		return err
	}

	return nil
}

func sendSeq(c net.Conn, seq uint64, payload string) error {
	intLen := len(payload) + ttyHdrSize
	payloadLen, err := uint64ToNBytesString(uint64(intLen), 4)
	if err != nil {
		return err
	}

	sequence, err := uint64ToNBytesString(uint64(seq), 8)
	if err != nil {
		return err
	}

	frame := frame{
		cmd:        sequence,
		payloadLen: payloadLen,
		payload:    payload,
	}

	err = send(c, frame)
	if err != nil {
		return err
	}

	return nil
}

func uint64ToNBytesString(val uint64, n int) (string, error) {
	var buf [8]byte

	if n < 1 || n > 8 {
		return "", fmt.Errorf("Invalid byte conversion")
	}

	for i := 0; i < n; i++ {
		buf[i] = byte(val >> uint((n-i-1)*8))
	}

	return string(buf[:n]), nil
}

func retryConnectSocket(retry int, sockType, sockName string) (net.Conn, error) {
	var err error
	var c net.Conn

	for i := 0; i < retry; i++ {
		c, err = net.Dial(sockType, sockName)
		if err == nil {
			break
		}

		select {
		case <-time.After(100 * time.Millisecond):
			break
		}
	}

	if err != nil {
		return nil, fmt.Errorf("Failed to dial on %s socket %s: %s\n", sockType, sockName, err)
	}

	return c, nil
}

func buildHyperContainerProcess(cmd Cmd) (hyperJson.Process, error) {
	var envVars []hyperJson.EnvironmentVar

	for _, e := range cmd.Envs {
		envVar := hyperJson.EnvironmentVar{
			Env:   e.Var,
			Value: e.Value,
		}

		envVars = append(envVars, envVar)
	}

	process := hyperJson.Process{
		User:    cmd.User,
		Group:   cmd.Group,
		Stdio:   uint64(rand.Int63()),
		Stderr:  uint64(rand.Int63()),
		Args:    cmd.Args,
		Envs:    envVars,
		Workdir: cmd.WorkDir,
	}

	return process, nil
}

func isStarted(c net.Conn, chType chType) bool {
	ret := false
	timeoutDuration := 1 * time.Second

	if c == nil {
		return ret
	}

	c.SetDeadline(time.Now().Add(timeoutDuration))

	switch chType {
	case ctlType:
		err := sendCmd(c, ping, nil)
		if err == nil {
			ret = true
		}
	case ttyType:
		err := sendSeq(c, uint64(0), "")
		if err != nil {
			break
		}

		_, err = recv(c, ttyType)
		if err == nil {
			ret = true
		}
	}

	c.SetDeadline(time.Time{})
	return ret
}

// init is the agent initialization implementation for hyperstart.
func (h *hyper) init(config interface{}, hypervisor hypervisor) error {
	switch c := config.(type) {
	case HyperConfig:
		if c.validate() == false {
			return fmt.Errorf("Invalid configuration\n")
		}
		h.config = c
	default:
		return fmt.Errorf("Invalid config type\n")
	}

	h.hypervisor = hypervisor

	for _, sharedDir := range h.config.Volumes {
		err := h.hypervisor.addDevice(sharedDir, fsDev)
		if err != nil {
			return err
		}
	}

	return nil
}

// start is the agent starting implementation for hyperstart.
func (h *hyper) start() error {
	var err error

	if isStarted(h.cCtl, ctlType) == true {
		return nil
	}

	h.cCtl, err = retryConnectSocket(1000, h.config.SockCtlType, h.config.SockCtlName)
	if err != nil {
		return err
	}

	err = sendCmd(h.cCtl, ping, nil)
	if err != nil {
		return err
	}

	h.cTty, err = retryConnectSocket(1000, h.config.SockTtyType, h.config.SockTtyName)
	if err != nil {
		return err
	}

	return nil
}

// exec is the agent command execution implementation for hyperstart.
func (h *hyper) exec(podID string, contID string, cmd Cmd) error {
	process, err := buildHyperContainerProcess(cmd)
	if err != nil {
		return err
	}

	execInfo := ExecInfo{
		Container: contID,
		Process:   process,
	}

	err = sendCmd(h.cCtl, execCommand, execInfo)
	if err != nil {
		return err
	}

	return nil
}

// startPod is the agent Pod starting implementation for hyperstart.
func (h *hyper) startPod(config PodConfig) error {
	var containers []hyperJson.Container

	for _, c := range config.Containers {
		process, err := buildHyperContainerProcess(c.Cmd)
		if err != nil {
			return err
		}

		container := hyperJson.Container{
			Id:      c.ID,
			Rootfs:  c.RootFs,
			Process: process,
		}

		containers = append(containers, container)
	}

	var mountTag string
	if h.config.Volumes != nil {
		mountTag = h.config.Volumes[0].MountTag
	} else {
		mountTag = ""
	}

	hyperPod := hyperJson.Pod{
		Hostname:   config.ID,
		Containers: containers,
		ShareDir:   mountTag,
	}

	err := sendCmd(h.cCtl, startPod, hyperPod)
	if err != nil {
		return err
	}

	return nil
}

// stopPod is the agent Pod stopping implementation for hyperstart.
func (h *hyper) stopPod(config PodConfig) error {
	err := sendCmd(h.cCtl, destroyPod, nil)
	if err != nil {
		return err
	}

	return nil
}

// stop is the agent stopping implementation for hyperstart.
func (h *hyper) stop() error {
	if h.cCtl == nil {
		return fmt.Errorf("Cannot close CTL channel, fd is nil")
	}

	err := h.cCtl.Close()
	if err != nil {
		return err
	}
	h.cCtl = nil

	if h.cTty == nil {
		return fmt.Errorf("Cannot close TTY channel, fd is nil")
	}

	err = h.cTty.Close()
	if err != nil {
		return err
	}
	h.cTty = nil

	return nil
}
