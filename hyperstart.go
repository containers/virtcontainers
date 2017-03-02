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
	"os"
	"path/filepath"
	"syscall"

	"github.com/golang/glog"

	"github.com/containers/virtcontainers/pkg/hyperstart"
	hyperJson "github.com/hyperhq/runv/hyperstart/api/json"
)

var defaultSockPathTemplates = []string{"/tmp/hyper-pod-%s.sock", "/tmp/tty-pod%s.sock"}
var defaultChannelTemplate = "sh.hyper.channel.%d"
var defaultDeviceIDTemplate = "channel%d"
var defaultIDTemplate = "charch%d"
var defaultSharedDir = "/tmp/hyper/shared/pods/"
var defaultPauseBinDir = "/usr/bin/"
var mountTag = "hyperShared"
var rootfsDir = "rootfs"
var pauseBinName = "pause"
var pauseContainerName = "pause-container"

const (
	unixSocket = "unix"
)

// HyperConfig is a structure storing information needed for
// hyperstart agent initialization.
type HyperConfig struct {
	SockCtlName  string
	SockTtyName  string
	Volumes      []Volume
	Sockets      []Socket
	PauseBinPath string
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

	if c.PauseBinPath == "" {
		c.PauseBinPath = filepath.Join(defaultPauseBinDir, pauseBinName)
	}

	glog.Infof("Hyperstart config %v\n", c)

	return true
}

// hyper is the Agent interface implementation for hyperstart.
type hyper struct {
	pod    *Pod
	config HyperConfig
	proxy  proxy
}

// ExecInfo is the structure corresponding to the format
// expected by hyperstart to execute a command on the guest.
type ExecInfo struct {
	Container string            `json:"container"`
	Process   hyperJson.Process `json:"process"`
}

// KillCommand is the structure corresponding to the format
// expected by hyperstart to kill a container on the guest.
type KillCommand struct {
	Container string         `json:"container"`
	Signal    syscall.Signal `json:"signal"`
}

// RemoveContainer is the structure corresponding to the format
// expected by hyperstart to remove a container on the guest.
type RemoveContainer struct {
	Container string `json:"container"`
}

type hyperstartProxyCmd struct {
	cmd     string
	message interface{}
}

func (h *hyper) buildHyperContainerProcess(cmd Cmd, stdio uint64, stderr uint64, terminal bool) (*hyperJson.Process, error) {
	var envVars []hyperJson.EnvironmentVar

	for _, e := range cmd.Envs {
		envVar := hyperJson.EnvironmentVar{
			Env:   e.Var,
			Value: e.Value,
		}

		envVars = append(envVars, envVar)
	}

	process := &hyperJson.Process{
		User:     cmd.User,
		Group:    cmd.Group,
		Terminal: terminal,
		Stdio:    stdio,
		Stderr:   stderr,
		Args:     cmd.Args,
		Envs:     envVars,
		Workdir:  cmd.WorkDir,
	}

	return process, nil
}

func (h *hyper) linkPauseBinary() error {
	pauseDir := filepath.Join(defaultSharedDir, h.pod.id, pauseContainerName, rootfsDir)

	err := os.MkdirAll(pauseDir, dirMode)
	if err != nil {
		return err
	}

	pausePath := filepath.Join(pauseDir, pauseBinName)

	return os.Link(h.config.PauseBinPath, pausePath)
}

func (h *hyper) unlinkPauseBinary() error {
	pauseDir := filepath.Join(defaultSharedDir, h.pod.id, pauseContainerName)

	return os.RemoveAll(pauseDir)
}

func (h *hyper) bindMountContainerRootfs(container ContainerConfig) error {
	rootfsDest := filepath.Join(defaultSharedDir, h.pod.id, container.ID)

	return bindMount(container.RootFs, rootfsDest)
}

func (h *hyper) bindUnmountContainerRootfs(container ContainerConfig) error {
	rootfsDest := filepath.Join(defaultSharedDir, h.pod.id, container.ID)
	syscall.Unmount(rootfsDest, 0)

	return nil
}

func (h *hyper) bindUnmountAllRootfs() {
	for _, c := range h.pod.containers {
		if c.config == nil {
			continue
		}

		h.bindUnmountContainerRootfs(*(c.config))
	}
}

// init is the agent initialization implementation for hyperstart.
func (h *hyper) init(pod *Pod, config interface{}) error {
	switch c := config.(type) {
	case HyperConfig:
		if c.validate(*pod) == false {
			return fmt.Errorf("Invalid configuration")
		}
		h.config = c
	default:
		return fmt.Errorf("Invalid config type")
	}

	pod.config.AgentConfig = h.config
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

	// Adding the hyper shared volume.
	// This volume contains all bind mounted container bundles.
	sharedVolume := Volume{
		MountTag: mountTag,
		HostPath: filepath.Join(defaultSharedDir, pod.id),
	}

	err := os.MkdirAll(sharedVolume.HostPath, dirMode)
	if err != nil {
		return err
	}

	err = h.pod.hypervisor.addDevice(sharedVolume, fsDev)
	if err != nil {
		return err
	}

	h.proxy, err = newProxy(pod.config.ProxyType)
	if err != nil {
		return err
	}

	return nil
}

// start is the agent starting implementation for hyperstart.
func (h *hyper) startAgent() error {
	proxyInfos, err := h.proxy.register(*(h.pod), true)
	if err != nil {
		return err
	}

	if len(proxyInfos) != len(h.pod.containers) {
		return fmt.Errorf("Retrieved %d proxy infos, expecting %d", len(proxyInfos), len(h.pod.containers))
	}

	for idx := range h.pod.containers {
		h.pod.containers[idx].process = Process{
			Token:  proxyInfos[idx].Token,
			Stdio:  proxyInfos[idx].StdioID,
			Stderr: proxyInfos[idx].StderrID,
		}

		if err := h.pod.containers[idx].storeProcess(); err != nil {
			return err
		}
	}

	return h.proxy.disconnect()
}

// exec is the agent command execution implementation for hyperstart.
func (h *hyper) exec(pod Pod, container Container, cmd Cmd) (*Process, error) {
	proxyInfo, err := h.proxy.connect(pod, true)
	if err != nil {
		return nil, err
	}

	process, err := h.buildHyperContainerProcess(cmd, proxyInfo.StdioID, proxyInfo.StderrID, container.config.Interactive)
	if err != nil {
		return nil, err
	}

	execInfo := ExecInfo{
		Container: container.id,
		Process:   *process,
	}

	proxyCmd := hyperstartProxyCmd{
		cmd:     hyperstart.ExecCmd,
		message: execInfo,
	}

	if _, err := h.proxy.sendCmd(proxyCmd); err != nil {
		return nil, err
	}

	if err := h.proxy.disconnect(); err != nil {
		return nil, err
	}

	processInfo := &Process{
		Token: proxyInfo.Token,
	}

	return processInfo, nil
}

// startPod is the agent Pod starting implementation for hyperstart.
func (h *hyper) startPod(config PodConfig) error {
	if _, err := h.proxy.connect(*(h.pod), false); err != nil {
		return err
	}

	var proxyInfos []ProxyInfo
	for _, c := range h.pod.containers {
		proxyInfo := ProxyInfo{
			StdioID:  c.process.Stdio,
			StderrID: c.process.Stderr,
		}

		proxyInfos = append(proxyInfos, proxyInfo)
	}

	if len(proxyInfos) != len(config.Containers) {
		return fmt.Errorf("Retrieved %d proxy infos, expecting %d", len(proxyInfos), len(config.Containers))
	}

	hyperPod := hyperJson.Pod{
		Hostname:             config.ID,
		DeprecatedContainers: []hyperJson.Container{},
		ShareDir:             mountTag,
	}

	proxyCmd := hyperstartProxyCmd{
		cmd:     hyperstart.StartPod,
		message: hyperPod,
	}

	if _, err := h.proxy.sendCmd(proxyCmd); err != nil {
		return err
	}

	if err := h.startPauseContainer(*(h.pod)); err != nil {
		return err
	}

	for idx, c := range config.Containers {
		err := h.startOneContainer(*(h.pod), c, proxyInfos[idx])
		if err != nil {
			return err
		}
	}

	return h.proxy.disconnect()
}

// stopPod is the agent Pod stopping implementation for hyperstart.
func (h *hyper) stopPod(pod Pod) error {
	_, err := h.proxy.connect(pod, false)
	if err != nil {
		return err
	}

	for _, contConfig := range pod.config.Containers {
		state, err := pod.storage.fetchContainerState(pod.id, contConfig.ID)
		if err != nil {
			return err
		}

		if state.State != StateRunning {
			continue
		}

		container := Container{
			id: contConfig.ID,
		}

		if err := h.killOneContainer(container, syscall.SIGTERM); err != nil {
			return err
		}

		if err := h.stopOneContainer(contConfig); err != nil {
			return err
		}
	}

	err = h.stopPauseContainer()
	if err != nil {
		return err
	}

	err = h.proxy.disconnect()
	if err != nil {
		return err
	}

	return nil
}

// stop is the agent stopping implementation for hyperstart.
func (h *hyper) stopAgent() error {
	if _, err := h.proxy.connect(*(h.pod), false); err != nil {
		return err
	}

	if err := h.proxy.unregister(*(h.pod)); err != nil {
		return err
	}

	return h.proxy.disconnect()
}

// startPauseContainer starts a specific container running the pause binary provided.
func (h *hyper) startPauseContainer(pod Pod) error {
	cmd := Cmd{
		Args:    []string{fmt.Sprintf("./%s", pauseBinName)},
		Envs:    []EnvVar{},
		WorkDir: "/",
	}

	process, err := h.buildHyperContainerProcess(cmd, ^uint64(0)-1, ^uint64(0), false)
	if err != nil {
		return err
	}

	container := hyperJson.Container{
		Id:      pauseContainerName,
		Image:   pauseContainerName,
		Rootfs:  rootfsDir,
		Process: process,
	}

	err = h.linkPauseBinary()
	if err != nil {
		return err
	}

	proxyCmd := hyperstartProxyCmd{
		cmd:     hyperstart.NewContainer,
		message: container,
	}

	_, err = h.proxy.sendCmd(proxyCmd)
	if err != nil {
		return err
	}

	return nil
}

func (h *hyper) startOneContainer(pod Pod, contConfig ContainerConfig, proxyInfo ProxyInfo) error {
	process, err := h.buildHyperContainerProcess(contConfig.Cmd, proxyInfo.StdioID, proxyInfo.StderrID, contConfig.Interactive)
	if err != nil {
		return err
	}

	container := hyperJson.Container{
		Id:      contConfig.ID,
		Image:   contConfig.ID,
		Rootfs:  rootfsDir,
		Process: process,
	}

	err = h.bindMountContainerRootfs(contConfig)
	if err != nil {
		h.bindUnmountAllRootfs()
		return err
	}

	proxyCmd := hyperstartProxyCmd{
		cmd:     hyperstart.NewContainer,
		message: container,
	}

	_, err = h.proxy.sendCmd(proxyCmd)
	if err != nil {
		return err
	}

	return nil
}

// createContainer is the agent Container creation implementation for hyperstart.
func (h *hyper) createContainer(contConfig ContainerConfig) error {
	proxyInfo, err := h.proxy.connect(*(h.pod), true)
	if err != nil {
		return err
	}

	container := &Container{
		id:    contConfig.ID,
		podID: h.pod.id,
		pod:   h.pod,
		process: Process{
			Token:  proxyInfo.Token,
			Stdio:  proxyInfo.StdioID,
			Stderr: proxyInfo.StderrID,
		},
	}

	if err := container.storeProcess(); err != nil {
		return err
	}

	return h.proxy.disconnect()
}

// startContainer is the agent Container starting implementation for hyperstart.
func (h *hyper) startContainer(pod Pod, contConfig ContainerConfig) error {
	_, err := h.proxy.connect(pod, false)
	if err != nil {
		return err
	}

	var proxyInfo ProxyInfo
	containerFound := false
	for _, c := range h.pod.containers {
		if c.id != contConfig.ID {
			continue
		}

		proxyInfo.StdioID = c.process.Stdio
		proxyInfo.StderrID = c.process.Stderr

		containerFound = true

		break
	}

	if containerFound == false {
		return fmt.Errorf("Could not find container %s in the pod", contConfig.ID)
	}

	err = h.startOneContainer(pod, contConfig, proxyInfo)
	if err != nil {
		return err
	}

	return h.proxy.disconnect()
}

func (h *hyper) stopPauseContainer() error {
	container := Container{
		id: pauseContainerName,
	}

	if err := h.killOneContainer(container, syscall.SIGKILL); err != nil {
		return err
	}

	if err := h.unlinkPauseBinary(); err != nil {
		return err
	}

	return nil
}

// stopContainer is the agent Container stopping implementation for hyperstart.
func (h *hyper) stopContainer(pod Pod, container Container) error {
	_, err := h.proxy.connect(pod, false)
	if err != nil {
		return err
	}

	err = h.stopOneContainer(*(container.config))
	if err != nil {
		return err
	}

	err = h.proxy.disconnect()
	if err != nil {
		return err
	}

	return nil
}

func (h *hyper) stopOneContainer(contConfig ContainerConfig) error {
	removeContainer := RemoveContainer{
		Container: contConfig.ID,
	}

	proxyCmd := hyperstartProxyCmd{
		cmd:     hyperstart.RemoveContainer,
		message: removeContainer,
	}

	_, err := h.proxy.sendCmd(proxyCmd)
	if err != nil {
		return err
	}

	err = h.bindUnmountContainerRootfs(contConfig)
	if err != nil {
		return err
	}

	return nil
}

// killContainer is the agent process signal implementation for hyperstart.
func (h *hyper) killContainer(pod Pod, container Container, signal syscall.Signal) error {
	if _, err := h.proxy.connect(pod, false); err != nil {
		return err
	}

	if err := h.killOneContainer(container, signal); err != nil {
		return err
	}

	if err := h.proxy.disconnect(); err != nil {
		return err
	}

	return nil
}

func (h *hyper) killOneContainer(container Container, signal syscall.Signal) error {
	killCmd := KillCommand{
		Container: container.id,
		Signal:    signal,
	}

	proxyCmd := hyperstartProxyCmd{
		cmd:     hyperstart.KillContainer,
		message: killCmd,
	}

	if _, err := h.proxy.sendCmd(proxyCmd); err != nil {
		return err
	}

	return nil
}
