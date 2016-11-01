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
	"fmt"
	"math/rand"
	"path/filepath"
	"syscall"
	"time"

	"github.com/golang/glog"

	hyperJson "github.com/hyperhq/runv/hyperstart/api/json"
	"github.com/sameo/virtcontainers/hyperstart"
)

var defaultSockPathTemplates = []string{"/tmp/hyper-pod-%s.sock", "/tmp/tty-pod%s.sock"}
var defaultChannelTemplate = "sh.hyper.channel.%d"
var defaultDeviceIDTemplate = "channel%d"
var defaultIDTemplate = "charch%d"
var defaultSharedDir = "/tmp/hyper/shared/pods/"
var mountTag = "hyperShared"

const (
	unixSocket = "unix"
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

	hyperstart *hyperstart.Hyperstart
}

// ExecInfo is the structure corresponding to the format
// expected by hyperstart to execute a command on the guest.
type ExecInfo struct {
	Container string            `json:"container"`
	Process   hyperJson.Process `json:"process"`
}

func (h *hyper) retryConnectSocket(retry int) error {
	var err error

	for i := 0; i < retry; i++ {
		err = h.hyperstart.OpenSockets()
		if err == nil {
			break
		}

		select {
		case <-time.After(100 * time.Millisecond):
			break
		}
	}

	return err
}

func (h *hyper) buildHyperContainerProcess(cmd Cmd) (hyperJson.Process, error) {
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

	h.hyperstart = hyperstart.NewHyperstart(h.config.SockCtlName, h.config.SockTtyName, unixSocket)

	return nil
}

// start is the agent starting implementation for hyperstart.
func (h *hyper) startAgent() error {
	if h.hyperstart.IsStarted() == true {
		return nil
	}

	err := h.retryConnectSocket(1000)
	if err != nil {
		return err
	}

	_, err = h.hyperstart.SendCtlMessage(hyperstart.Ping, nil)
	if err != nil {
		return err
	}

	return nil
}

// exec is the agent command execution implementation for hyperstart.
func (h *hyper) exec(podID string, contID string, cmd Cmd) error {
	process, err := h.buildHyperContainerProcess(cmd)
	if err != nil {
		return err
	}

	execInfo := ExecInfo{
		Container: contID,
		Process:   process,
	}

	payload, err := hyperstart.FormatMessage(execInfo)
	if err != nil {
		return err
	}

	_, err = h.hyperstart.SendCtlMessage(hyperstart.ExecCmd, payload)
	if err != nil {
		return err
	}

	return nil
}

// startPod is the agent Pod starting implementation for hyperstart.
func (h *hyper) startPod(config PodConfig) error {
	var containers []hyperJson.Container

	for _, c := range config.Containers {
		process, err := h.buildHyperContainerProcess(c.Cmd)
		if err != nil {
			return err
		}

		container := hyperJson.Container{
			Id:      c.ID,
			Image:   c.ID,
			Rootfs:  "rootfs",
			Process: process,
		}

		containers = append(containers, container)
	}

	hyperPod := hyperJson.Pod{
		Hostname:   config.ID,
		Containers: containers,
		ShareDir:   mountTag,
	}

	payload, err := hyperstart.FormatMessage(hyperPod)
	if err != nil {
		return err
	}

	_, err = h.hyperstart.SendCtlMessage(hyperstart.StartPod, payload)
	if err != nil {
		return err
	}

	return nil
}

// stopPod is the agent Pod stopping implementation for hyperstart.
func (h *hyper) stopPod(config PodConfig) error {
	_, err := h.hyperstart.SendCtlMessage(hyperstart.DestroyPod, nil)
	if err != nil {
		return err
	}

	return nil
}

// stop is the agent stopping implementation for hyperstart.
func (h *hyper) stopAgent() error {
	err := h.hyperstart.CloseSockets()
	if err != nil {
		return err
	}

	bindUnmountAllRootfs(h.pod)

	return nil
}
