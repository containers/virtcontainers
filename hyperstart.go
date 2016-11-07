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
	"fmt"
	"math/rand"
	"net"
	"path/filepath"
	"syscall"
	"time"

	"github.com/golang/glog"

	hyperJson "github.com/hyperhq/runv/hyperstart/api/json"
)

var defaultSockPathTemplates = []string{"/tmp/hyper-pod-%s.sock", "/tmp/tty-pod%s.sock"}
var defaultChannelTemplate = "sh.hyper.channel.%d"
var defaultDeviceIDTemplate = "channel%d"
var defaultIDTemplate = "charch%d"
var defaultSharedDir = "/tmp/hyper/shared/pods/"
var mountTag = "hyperShared"

// Control command IDs
// Need to be in sync with hyperstart/src/api.h
const (
	getVersion        uint32 = 0
	startPod                 = 1
	getPod                   = 2
	stopPodDeprecated        = 3
	destroyPod               = 4
	restartContainer         = 5
	execCommand              = 6
	cmdFinished              = 7
	ready                    = 8
	ack                      = 9
	hyperError               = 10
	winSize                  = 11
	ping                     = 12
	podFinished              = 13
	next                     = 14
	writeFile                = 15
	readFile                 = 16
	newContainer             = 17
	killContainer            = 18
	onlineCPUMem             = 19
	setupInterface           = 20
	setupRoute               = 21
	removeContainer          = 22
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

// HyperstartChType differentiates channels type.
type HyperstartChType uint8

// List of possible values for channels type.
const (
	HyperstartCtlType HyperstartChType = iota
	HyperstartTtyType
)

// HyperConfig is a structure storing information needed for
// hyperstart agent initialization.
type HyperConfig struct {
	SockCtlName string
	SockTtyName string
	Volumes     []Volume
	Sockets     []Socket
}

func (c *HyperConfig) validate(pod Pod) bool {
	if len(c.Sockets) == 0 {
		glog.Infof("No sockets from configuration\n")

		podSocketPaths := []string{
			fmt.Sprintf(defaultSockPathTemplates[0], pod.id),
			fmt.Sprintf(defaultSockPathTemplates[1], pod.id),
		}

		c.SockCtlName = podSocketPaths[0]
		c.SockTtyName = podSocketPaths[1]

		for i := 0; i < len(podSocketPaths); i++ {
			s := Socket{
				DeviceID: fmt.Sprintf(defaultDeviceIDTemplate, i),
				ID:       fmt.Sprintf(defaultIDTemplate, i),
				HostPath: podSocketPaths[i],
				Name:     fmt.Sprintf(defaultChannelTemplate, i),
			}
			c.Sockets = append(c.Sockets, s)
		}
	}

	if len(c.Sockets) != 2 {
		return false
	}

	glog.Infof("Hyperstart config %v\n", c)

	return true
}

// hyper is the Agent interface implementation for hyperstart.
type hyper struct {
	pod    Pod
	config HyperConfig

	cCtl net.Conn
	cTty net.Conn
}

// HyperstartFrame is the structure corresponding to the frame format
// used to send and receive on different channels.
type HyperstartFrame struct {
	Cmd        string
	PayloadLen string
	Payload    string
}

// ExecInfo is the structure corresponding to the format
// expected by hyperstart to execute a command on the guest.
type ExecInfo struct {
	Container string            `json:"container"`
	Process   hyperJson.Process `json:"process"`
}

// HyperstartSend is the API to send messages to hyperstart in the VM.
func HyperstartSend(c net.Conn, frame HyperstartFrame) error {
	strArray := frame.Cmd + frame.PayloadLen + frame.Payload

	c.Write([]byte(strArray))

	return nil
}

// HyperstartRecv is the API to receive messages from hyperstart in the VM.
func HyperstartRecv(c net.Conn, chType HyperstartChType) (HyperstartFrame, error) {
	var frame HyperstartFrame
	var hdrSize int
	var hdrLenOffset int

	switch chType {
	case HyperstartCtlType:
		hdrSize = ctlHdrSize
		hdrLenOffset = ctlHdrLenOffset
	case HyperstartTtyType:
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

	frame.Cmd = string(byteHdr[:hdrLenOffset])
	frame.PayloadLen = string(byteHdr[hdrLenOffset:])

	payloadLen := binary.BigEndian.Uint32(byteHdr[hdrLenOffset:]) - uint32(hdrSize)
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
	if chType == HyperstartTtyType {
		glog.Infof("String formatted payload: %s\n", string(bytePayload))
	}

	if byteRead != int(payloadLen) {
		return frame, fmt.Errorf("Not enough bytes read (%d/%d)\n", byteRead, payloadLen)
	}

	frame.Payload = string(bytePayload)

	return frame, nil
}

func waitForReply(c net.Conn, cmdID uint32) error {
	for {
		frame, err := HyperstartRecv(c, HyperstartCtlType)
		if err != nil {
			return err
		}

		fCmd := binary.BigEndian.Uint32([]byte(frame.Cmd))

		if fCmd == cmdID {
			break
		}

		if fCmd == next || fCmd == ready {
			continue
		}

		glog.Infof("Received command %d\n", fCmd)

		if fCmd != cmdID {
			if fCmd == hyperError {
				return fmt.Errorf("ERROR received from Hyperstart\n")
			}

			return fmt.Errorf("CMD ID received %d not matching expected %d\n", fCmd, cmdID)
		}
	}

	return nil
}

// FormatHyperstartFrame is the API to format hyperstart messages.
func FormatHyperstartFrame(cmd uint64, payload interface{}, chType HyperstartChType) (HyperstartFrame, error) {
	var payloadStr string
	var hdrSize int
	var hdrLenOffset int

	if payload != nil {
		switch p := payload.(type) {
		case string:
			payloadStr = p
		default:
			jsonOut, err := json.Marshal(p)
			if err != nil {
				return HyperstartFrame{}, err
			}

			payloadStr = string(jsonOut)
		}
	} else {
		payloadStr = ""
	}

	glog.Infof("payload: %s\n", payloadStr)

	switch chType {
	case HyperstartCtlType:
		hdrSize = ctlHdrSize
		hdrLenOffset = ctlHdrLenOffset
	case HyperstartTtyType:
		hdrSize = ttyHdrSize
		hdrLenOffset = ttyHdrLenOffset
	}

	payloadLen := len(payloadStr) + hdrSize
	payloadLenStr, err := uint64ToNBytesString(uint64(payloadLen), hdrSize-hdrLenOffset)
	if err != nil {
		return HyperstartFrame{}, err
	}

	glog.Infof("payload len: %x\n", payloadLenStr)

	cmdStr, err := uint64ToNBytesString(cmd, hdrLenOffset)
	if err != nil {
		return HyperstartFrame{}, err
	}

	frame := HyperstartFrame{
		Cmd:        cmdStr,
		PayloadLen: payloadLenStr,
		Payload:    payloadStr,
	}

	return frame, nil
}

func sendCmd(c net.Conn, cmd uint32, payload interface{}) error {
	frame, err := FormatHyperstartFrame(uint64(cmd), payload, HyperstartCtlType)
	if err != nil {
		return err
	}

	err = HyperstartSend(c, frame)
	if err != nil {
		return err
	}

	if cmd == destroyPod {
		return nil
	}

	err = waitForReply(c, ack)
	if err != nil {
		return err
	}

	return nil
}

func sendSeq(c net.Conn, seq uint64, payload string) error {
	frame, err := FormatHyperstartFrame(seq, payload, HyperstartTtyType)
	if err != nil {
		return err
	}

	err = HyperstartSend(c, frame)
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

func (h *hyper) isStarted(c net.Conn, chType HyperstartChType) bool {
	ret := false
	timeoutDuration := 1 * time.Second

	if c == nil {
		return ret
	}

	c.SetDeadline(time.Now().Add(timeoutDuration))

	switch chType {
	case HyperstartCtlType:
		err := sendCmd(c, ping, nil)
		if err == nil {
			ret = true
		}
	case HyperstartTtyType:
		err := sendSeq(c, uint64(0), "")
		if err != nil {
			break
		}

		_, err = HyperstartRecv(c, HyperstartTtyType)
		if err == nil {
			ret = true
		}
	}

	c.SetDeadline(time.Time{})

	if ret == false {
		h.stopAgent()
	}

	return ret
}

func bindMountContainerRootfs(pod Pod, container ContainerConfig) error {
	rootfsDest := filepath.Join(defaultSharedDir, pod.id, container.ID)

	return bindMount(container.RootFs, rootfsDest)
}

func bindUnmountAllRootfs(pod Pod) {
	for _, c := range pod.containers {
		rootfsDest := filepath.Join(defaultSharedDir, pod.id, c.ID)
		syscall.Unmount(rootfsDest, 0)
	}
}

// init is the agent initialization implementation for hyperstart.
func (h *hyper) init(pod Pod, config interface{}) error {
	switch c := config.(type) {
	case HyperConfig:
		if c.validate(pod) == false {
			return fmt.Errorf("Invalid configuration\n")
		}
		h.config = c
	default:
		return fmt.Errorf("Invalid config type\n")
	}

	h.pod = pod

	for _, volume := range h.config.Volumes {
		err := h.pod.hypervisor.addDevice(volume, fsDev)
		if err != nil {
			return err
		}
	}

	for _, socket := range h.config.Sockets {
		err := h.pod.hypervisor.addDevice(socket, serialPortDev)
		if err != nil {
			return err
		}
	}

	for _, c := range pod.containers {
		err := bindMountContainerRootfs(pod, c)
		if err != nil {
			bindUnmountAllRootfs(pod)
			return err
		}
	}

	// Adding the hyper shared volume.
	// This volume contains all bind mounted container bundles.
	sharedVolume := Volume{
		MountTag: mountTag,
		HostPath: filepath.Join(defaultSharedDir, pod.id),
	}

	err := h.pod.hypervisor.addDevice(sharedVolume, fsDev)
	if err != nil {
		return err
	}

	return nil
}

// start is the agent starting implementation for hyperstart.
func (h *hyper) startAgent() error {
	var err error

	if h.isStarted(h.cCtl, HyperstartCtlType) == true {
		return nil
	}

	h.cCtl, err = retryConnectSocket(1000, "unix", h.config.SockCtlName)
	if err != nil {
		return err
	}

	err = sendCmd(h.cCtl, ping, nil)
	if err != nil {
		return err
	}

	h.cTty, err = retryConnectSocket(1000, "unix", h.config.SockTtyName)
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
			Image:   c.ID,
			Rootfs:  c.RootFs,
			Process: process,
		}

		containers = append(containers, container)
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
func (h *hyper) stopAgent() error {
	if h.cCtl != nil {
		err := h.cCtl.Close()
		if err != nil {
			return err
		}

		h.cCtl = nil
	}

	if h.cTty != nil {
		err := h.cTty.Close()
		if err != nil {
			return err
		}

		h.cTty = nil
	}

	bindUnmountAllRootfs(h.pod)

	return nil
}
