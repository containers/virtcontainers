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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/containers/virtcontainers/hyperstart/mock"
)

const (
	TestHyperstartCtlSocket = "/tmp/test_hyper.sock"
	TestHyperstartTtySocket = "/tmp/test_tty.sock"
)

func newBasicTestCmd() Cmd {
	envs := []EnvVar{
		{
			Var:   "PATH",
			Value: "/bin:/usr/bin:/sbin:/usr/sbin",
		},
	}

	cmd := Cmd{
		Args:    strings.Split("/bin/sh", " "),
		Envs:    envs,
		WorkDir: "/",
	}

	return cmd
}

func newTestPodConfigNoop() PodConfig {
	// Define the container command and bundle.
	container := ContainerConfig{
		ID:     "1",
		RootFs: filepath.Join(testDir, testBundle),
		Cmd:    newBasicTestCmd(),
	}

	// Sets the hypervisor configuration.
	hypervisorConfig := HypervisorConfig{
		KernelPath:     filepath.Join(testDir, testKernel),
		ImagePath:      filepath.Join(testDir, testImage),
		HypervisorPath: filepath.Join(testDir, testHypervisor),
	}

	podConfig := PodConfig{
		HypervisorType:   MockHypervisor,
		HypervisorConfig: hypervisorConfig,

		AgentType: NoopAgentType,

		Containers: []ContainerConfig{container},
	}

	return podConfig
}

func newTestPodConfigHyperstartAgent() PodConfig {
	// Define the container command and bundle.
	container := ContainerConfig{
		ID:     "1",
		RootFs: filepath.Join(testDir, testBundle),
		Cmd:    newBasicTestCmd(),
	}

	// Sets the hypervisor configuration.
	hypervisorConfig := HypervisorConfig{
		KernelPath:     filepath.Join(testDir, testKernel),
		ImagePath:      filepath.Join(testDir, testImage),
		HypervisorPath: filepath.Join(testDir, testHypervisor),
	}

	sockets := []Socket{{}, {}}

	agentConfig := HyperConfig{
		SockCtlName: TestHyperstartCtlSocket,
		SockTtyName: TestHyperstartTtySocket,
		Sockets:     sockets,
	}

	podConfig := PodConfig{
		HypervisorType:   MockHypervisor,
		HypervisorConfig: hypervisorConfig,

		AgentType:   HyperstartAgent,
		AgentConfig: agentConfig,

		Containers: []ContainerConfig{container},
	}

	return podConfig
}

func TestCreatePodNoopAgentSuccessful(t *testing.T) {
	config := newTestPodConfigNoop()

	p, err := CreatePod(config)
	if p == nil || err != nil {
		t.Fatal()
	}

	podDir := filepath.Join(configStoragePath, p.id)
	_, err = os.Stat(podDir)
	if err != nil {
		t.Fatal()
	}
}

func TestCreatePodHyperstartAgentSuccessful(t *testing.T) {
	config := newTestPodConfigHyperstartAgent()

	p, err := CreatePod(config)
	if p == nil || err != nil {
		t.Fatalf("%s", err)
	}

	podDir := filepath.Join(configStoragePath, p.id)
	_, err = os.Stat(podDir)
	if err != nil {
		t.Fatal()
	}
}

func TestCreatePodFailing(t *testing.T) {
	config := PodConfig{}

	p, err := CreatePod(config)
	if p != nil || err == nil {
		t.Fatal()
	}
}

func TestDeletePodNoopAgentSuccessful(t *testing.T) {
	config := newTestPodConfigNoop()

	p, err := CreatePod(config)
	if p == nil || err != nil {
		t.Fatal()
	}

	podDir := filepath.Join(configStoragePath, p.id)
	_, err = os.Stat(podDir)
	if err != nil {
		t.Fatal()
	}

	p, err = DeletePod(p.id)
	if p == nil || err != nil {
		t.Fatal()
	}

	_, err = os.Stat(podDir)
	if err == nil {
		t.Fatal()
	}
}

func TestDeletePodHyperstartAgentSuccessful(t *testing.T) {
	config := newTestPodConfigHyperstartAgent()

	p, err := CreatePod(config)
	if p == nil || err != nil {
		t.Fatal()
	}

	podDir := filepath.Join(configStoragePath, p.id)
	_, err = os.Stat(podDir)
	if err != nil {
		t.Fatal()
	}

	p, err = DeletePod(p.id)
	if p == nil || err != nil {
		t.Fatal()
	}

	_, err = os.Stat(podDir)
	if err == nil {
		t.Fatal()
	}
}

func TestDeletePodFailing(t *testing.T) {
	podDir := filepath.Join(configStoragePath, testPodID)
	os.Remove(podDir)

	p, err := DeletePod(testPodID)
	if p != nil || err == nil {
		t.Fatal()
	}
}

func TestStartPodNoopAgentSuccessful(t *testing.T) {
	config := newTestPodConfigNoop()

	p, err := CreatePod(config)
	if p == nil || err != nil {
		t.Fatal()
	}

	podDir := filepath.Join(configStoragePath, p.id)
	_, err = os.Stat(podDir)
	if err != nil {
		t.Fatal()
	}

	p, err = StartPod(p.id)
	if p == nil || err != nil {
		t.Fatal()
	}
}

func startMockHyperstart(t *testing.T) (string, string, *mock.Hyperstart) {
	mockHyper := mock.NewHyperstart(t)

	mockHyper.Start()

	ctlSockPath, ioSockPath := mockHyper.GetSocketPaths()

	return ctlSockPath, ioSockPath, mockHyper
}

func TestStartPodHyperstartAgentSuccessful(t *testing.T) {
	config := newTestPodConfigHyperstartAgent()

	ctlSockPath, ioSockPath, mock := startMockHyperstart(t)
	defer mock.Stop()

	hyperConfig := config.AgentConfig.(HyperConfig)
	hyperConfig.SockCtlName = ctlSockPath
	hyperConfig.SockTtyName = ioSockPath
	config.AgentConfig = hyperConfig

	p, err := CreatePod(config)
	if p == nil || err != nil {
		t.Fatal()
	}

	podDir := filepath.Join(configStoragePath, p.id)
	_, err = os.Stat(podDir)
	if err != nil {
		t.Fatal()
	}

	p, err = StartPod(p.id)
	if p == nil || err != nil {
		t.Fatal()
	}
}

func TestStartPodFailing(t *testing.T) {
	podDir := filepath.Join(configStoragePath, testPodID)
	os.Remove(podDir)

	p, err := StartPod(testPodID)
	if p != nil || err == nil {
		t.Fatal()
	}
}

func TestStopPodNoopAgentSuccessful(t *testing.T) {
	config := newTestPodConfigNoop()

	p, err := CreatePod(config)
	if p == nil || err != nil {
		t.Fatal()
	}

	podDir := filepath.Join(configStoragePath, p.id)
	_, err = os.Stat(podDir)
	if err != nil {
		t.Fatal()
	}

	p, err = StartPod(p.id)
	if p == nil || err != nil {
		t.Fatal()
	}

	p, err = StopPod(p.id)
	if p == nil || err != nil {
		t.Fatal()
	}
}

func TestStopPodHyperstartAgentSuccessful(t *testing.T) {
	config := newTestPodConfigHyperstartAgent()

	ctlSockPath, ioSockPath, mock := startMockHyperstart(t)

	hyperConfig := config.AgentConfig.(HyperConfig)
	hyperConfig.SockCtlName = ctlSockPath
	hyperConfig.SockTtyName = ioSockPath
	config.AgentConfig = hyperConfig

	p, err := CreatePod(config)
	if p == nil || err != nil {
		mock.Stop()
		t.Fatal()
	}

	podDir := filepath.Join(configStoragePath, p.id)
	_, err = os.Stat(podDir)
	if err != nil {
		mock.Stop()
		t.Fatal()
	}

	p, err = StartPod(p.id)
	if p == nil || err != nil {
		mock.Stop()
		t.Fatal()
	}

	mock.Stop()
	mock.Start()
	defer mock.Stop()

	p, err = StopPod(p.id)
	if p == nil || err != nil {
		t.Fatal()
	}
}

func TestStopPodFailing(t *testing.T) {
	podDir := filepath.Join(configStoragePath, testPodID)
	os.Remove(podDir)

	p, err := StopPod(testPodID)
	if p != nil || err == nil {
		t.Fatal()
	}
}

func TestRunPodNoopAgentSuccessful(t *testing.T) {
	config := newTestPodConfigNoop()

	p, err := RunPod(config)
	if p == nil || err != nil {
		t.Fatal()
	}

	podDir := filepath.Join(configStoragePath, p.id)
	_, err = os.Stat(podDir)
	if err != nil {
		t.Fatal()
	}
}

func TestRunPodHyperstartAgentSuccessful(t *testing.T) {
	config := newTestPodConfigHyperstartAgent()

	ctlSockPath, ioSockPath, mock := startMockHyperstart(t)
	defer mock.Stop()

	hyperConfig := config.AgentConfig.(HyperConfig)
	hyperConfig.SockCtlName = ctlSockPath
	hyperConfig.SockTtyName = ioSockPath
	config.AgentConfig = hyperConfig

	p, err := RunPod(config)
	if p == nil || err != nil {
		t.Fatal()
	}

	podDir := filepath.Join(configStoragePath, p.id)
	_, err = os.Stat(podDir)
	if err != nil {
		t.Fatal()
	}
}

func TestRunPodFailing(t *testing.T) {
	config := PodConfig{}

	p, err := RunPod(config)
	if p != nil || err == nil {
		t.Fatal()
	}
}

func TestListPodSuccessful(t *testing.T) {
	os.RemoveAll(configStoragePath)

	config := newTestPodConfigNoop()

	p, err := CreatePod(config)
	if p == nil || err != nil {
		t.Fatal()
	}

	err = ListPod()
	if err != nil {
		t.Fatal()
	}
}

func TestListPodFailing(t *testing.T) {
	os.RemoveAll(configStoragePath)

	err := ListPod()
	if err == nil {
		t.Fatal()
	}
}

func TestStatusPodSuccessful(t *testing.T) {
	config := newTestPodConfigNoop()

	p, err := CreatePod(config)
	if p == nil || err != nil {
		t.Fatal()
	}

	err = StatusPod(p.id)
	if err != nil {
		t.Fatal()
	}
}

func TestListPodFailingFetchPodConfig(t *testing.T) {
	config := newTestPodConfigNoop()

	p, err := CreatePod(config)
	if p == nil || err != nil {
		t.Fatal()
	}

	path := filepath.Join(configStoragePath, p.id)
	os.RemoveAll(path)

	err = StatusPod(p.id)
	if err == nil {
		t.Fatal()
	}
}

func TestListPodFailingFetchPodState(t *testing.T) {
	config := newTestPodConfigNoop()

	p, err := CreatePod(config)
	if p == nil || err != nil {
		t.Fatal()
	}

	path := filepath.Join(runStoragePath, p.id)
	os.RemoveAll(path)

	err = StatusPod(p.id)
	if err == nil {
		t.Fatal()
	}
}

func newTestContainerConfigNoop(contID string) ContainerConfig {
	// Define the container command and bundle.
	container := ContainerConfig{
		ID:     contID,
		RootFs: filepath.Join(testDir, testBundle),
		Cmd:    newBasicTestCmd(),
	}

	return container
}

func TestCreateContainerSuccessful(t *testing.T) {
	contID := "100"
	config := newTestPodConfigNoop()

	p, err := CreatePod(config)
	if p == nil || err != nil {
		t.Fatal()
	}

	podDir := filepath.Join(configStoragePath, p.id)
	_, err = os.Stat(podDir)
	if err != nil {
		t.Fatal()
	}

	contConfig := newTestContainerConfigNoop(contID)

	c, err := CreateContainer(p.id, contConfig)
	if c == nil || err != nil {
		t.Fatal()
	}

	contDir := filepath.Join(podDir, contID)
	_, err = os.Stat(contDir)
	if err != nil {
		t.Fatal()
	}
}

func TestCreateContainerFailingNoPod(t *testing.T) {
	contID := "100"
	config := newTestPodConfigNoop()

	p, err := CreatePod(config)
	if p == nil || err != nil {
		t.Fatal()
	}

	p, err = DeletePod(p.id)
	if p == nil || err != nil {
		t.Fatal()
	}

	podDir := filepath.Join(configStoragePath, p.id)
	_, err = os.Stat(podDir)
	if err == nil {
		t.Fatal()
	}

	contConfig := newTestContainerConfigNoop(contID)

	c, err := CreateContainer(p.id, contConfig)
	if c != nil || err == nil {
		t.Fatal()
	}
}

func TestDeleteContainerSuccessful(t *testing.T) {
	contID := "100"
	config := newTestPodConfigNoop()

	p, err := CreatePod(config)
	if p == nil || err != nil {
		t.Fatal()
	}

	podDir := filepath.Join(configStoragePath, p.id)
	_, err = os.Stat(podDir)
	if err != nil {
		t.Fatal()
	}

	contConfig := newTestContainerConfigNoop(contID)

	c, err := CreateContainer(p.id, contConfig)
	if c == nil || err != nil {
		t.Fatal()
	}

	contDir := filepath.Join(podDir, contID)
	_, err = os.Stat(contDir)
	if err != nil {
		t.Fatal()
	}

	c, err = DeleteContainer(p.id, contID)
	if c == nil || err != nil {
		t.Fatal()
	}

	_, err = os.Stat(contDir)
	if err == nil {
		t.Fatal()
	}
}

func TestDeleteContainerFailingNoPod(t *testing.T) {
	podDir := filepath.Join(configStoragePath, testPodID)
	contID := "100"
	os.RemoveAll(podDir)

	c, err := DeleteContainer(testPodID, contID)
	if c != nil || err == nil {
		t.Fatal()
	}
}

func TestDeleteContainerFailingNoContainer(t *testing.T) {
	contID := "100"
	config := newTestPodConfigNoop()

	p, err := CreatePod(config)
	if p == nil || err != nil {
		t.Fatal()
	}

	podDir := filepath.Join(configStoragePath, p.id)
	_, err = os.Stat(podDir)
	if err != nil {
		t.Fatal()
	}

	c, err := DeleteContainer(p.id, contID)
	if c != nil || err == nil {
		t.Fatal()
	}
}

func TestStartContainerNoopAgentSuccessful(t *testing.T) {
	contID := "100"
	config := newTestPodConfigNoop()

	p, err := CreatePod(config)
	if p == nil || err != nil {
		t.Fatal()
	}

	podDir := filepath.Join(configStoragePath, p.id)
	_, err = os.Stat(podDir)
	if err != nil {
		t.Fatal()
	}

	p, err = StartPod(p.id)
	if p == nil || err != nil {
		t.Fatal()
	}

	contConfig := newTestContainerConfigNoop(contID)

	c, err := CreateContainer(p.id, contConfig)
	if c == nil || err != nil {
		t.Fatal()
	}

	contDir := filepath.Join(podDir, contID)
	_, err = os.Stat(contDir)
	if err != nil {
		t.Fatal()
	}

	c, err = StartContainer(p.id, contID)
	if c == nil || err != nil {
		t.Fatal()
	}
}

func TestStartContainerHyperstartAgentSuccessful(t *testing.T) {
	contID := "100"
	config := newTestPodConfigHyperstartAgent()

	ctlSockPath, ioSockPath, mock := startMockHyperstart(t)

	hyperConfig := config.AgentConfig.(HyperConfig)
	hyperConfig.SockCtlName = ctlSockPath
	hyperConfig.SockTtyName = ioSockPath
	config.AgentConfig = hyperConfig

	p, err := CreatePod(config)
	if p == nil || err != nil {
		mock.Stop()
		t.Fatal()
	}

	podDir := filepath.Join(configStoragePath, p.id)
	_, err = os.Stat(podDir)
	if err != nil {
		mock.Stop()
		t.Fatal()
	}

	p, err = StartPod(p.id)
	if p == nil || err != nil {
		mock.Stop()
		t.Fatal()
	}

	mock.Stop()

	contConfig := newTestContainerConfigNoop(contID)

	c, err := CreateContainer(p.id, contConfig)
	if c == nil || err != nil {
		t.Fatal()
	}

	contDir := filepath.Join(podDir, contID)
	_, err = os.Stat(contDir)
	if err != nil {
		t.Fatal()
	}

	mock.Start()
	defer mock.Stop()

	c, err = StartContainer(p.id, contID)
	if c == nil || err != nil {
		t.Fatal()
	}
}

func TestStartContainerFailingNoPod(t *testing.T) {
	podDir := filepath.Join(configStoragePath, testPodID)
	contID := "100"
	os.RemoveAll(podDir)

	c, err := StartContainer(testPodID, contID)
	if c != nil || err == nil {
		t.Fatal()
	}
}

func TestStartContainerFailingNoContainer(t *testing.T) {
	contID := "100"
	config := newTestPodConfigNoop()

	p, err := CreatePod(config)
	if p == nil || err != nil {
		t.Fatal()
	}

	podDir := filepath.Join(configStoragePath, p.id)
	_, err = os.Stat(podDir)
	if err != nil {
		t.Fatal()
	}

	c, err := StartContainer(p.id, contID)
	if c != nil || err == nil {
		t.Fatal()
	}
}

func TestStartContainerFailingPodNotStarted(t *testing.T) {
	contID := "100"
	config := newTestPodConfigNoop()

	p, err := CreatePod(config)
	if p == nil || err != nil {
		t.Fatal()
	}

	podDir := filepath.Join(configStoragePath, p.id)
	_, err = os.Stat(podDir)
	if err != nil {
		t.Fatal()
	}

	contConfig := newTestContainerConfigNoop(contID)

	c, err := CreateContainer(p.id, contConfig)
	if c == nil || err != nil {
		t.Fatal()
	}

	contDir := filepath.Join(podDir, contID)
	_, err = os.Stat(contDir)
	if err != nil {
		t.Fatal()
	}

	c, err = StartContainer(p.id, contID)
	if c != nil || err == nil {
		t.Fatal()
	}
}

func TestStopContainerNoopAgentSuccessful(t *testing.T) {
	contID := "100"
	config := newTestPodConfigNoop()

	p, err := CreatePod(config)
	if p == nil || err != nil {
		t.Fatal()
	}

	podDir := filepath.Join(configStoragePath, p.id)
	_, err = os.Stat(podDir)
	if err != nil {
		t.Fatal()
	}

	p, err = StartPod(p.id)
	if p == nil || err != nil {
		t.Fatal()
	}

	contConfig := newTestContainerConfigNoop(contID)

	c, err := CreateContainer(p.id, contConfig)
	if c == nil || err != nil {
		t.Fatal()
	}

	contDir := filepath.Join(podDir, contID)
	_, err = os.Stat(contDir)
	if err != nil {
		t.Fatal()
	}

	c, err = StartContainer(p.id, contID)
	if c == nil || err != nil {
		t.Fatal()
	}

	c, err = StopContainer(p.id, contID)
	if c == nil || err != nil {
		t.Fatal()
	}
}

func TestStopContainerHyperstartAgentSuccessful(t *testing.T) {
	contID := "100"
	config := newTestPodConfigHyperstartAgent()

	ctlSockPath, ioSockPath, mock := startMockHyperstart(t)

	hyperConfig := config.AgentConfig.(HyperConfig)
	hyperConfig.SockCtlName = ctlSockPath
	hyperConfig.SockTtyName = ioSockPath
	config.AgentConfig = hyperConfig

	p, err := CreatePod(config)
	if p == nil || err != nil {
		mock.Stop()
		t.Fatal()
	}

	podDir := filepath.Join(configStoragePath, p.id)
	_, err = os.Stat(podDir)
	if err != nil {
		mock.Stop()
		t.Fatal()
	}

	p, err = StartPod(p.id)
	if p == nil || err != nil {
		mock.Stop()
		t.Fatal()
	}

	mock.Stop()

	contConfig := newTestContainerConfigNoop(contID)

	c, err := CreateContainer(p.id, contConfig)
	if c == nil || err != nil {
		t.Fatal()
	}

	contDir := filepath.Join(podDir, contID)
	_, err = os.Stat(contDir)
	if err != nil {
		t.Fatal()
	}

	mock.Start()

	c, err = StartContainer(p.id, contID)
	if c == nil || err != nil {
		mock.Stop()
		t.Fatal()
	}

	mock.Stop()
	mock.Start()
	defer mock.Stop()

	c, err = StopContainer(p.id, contID)
	if c == nil || err != nil {
		t.Fatal()
	}
}

func TestStopContainerFailingNoPod(t *testing.T) {
	podDir := filepath.Join(configStoragePath, testPodID)
	contID := "100"
	os.RemoveAll(podDir)

	c, err := StopContainer(testPodID, contID)
	if c != nil || err == nil {
		t.Fatal()
	}
}

func TestStopContainerFailingNoContainer(t *testing.T) {
	contID := "100"
	config := newTestPodConfigNoop()

	p, err := CreatePod(config)
	if p == nil || err != nil {
		t.Fatal()
	}

	podDir := filepath.Join(configStoragePath, p.id)
	_, err = os.Stat(podDir)
	if err != nil {
		t.Fatal()
	}

	c, err := StopContainer(p.id, contID)
	if c != nil || err == nil {
		t.Fatal()
	}
}

func TestStopContainerFailingContNotStarted(t *testing.T) {
	contID := "100"
	config := newTestPodConfigNoop()

	p, err := CreatePod(config)
	if p == nil || err != nil {
		t.Fatal()
	}

	podDir := filepath.Join(configStoragePath, p.id)
	_, err = os.Stat(podDir)
	if err != nil {
		t.Fatal()
	}

	p, err = StartPod(p.id)
	if p == nil || err != nil {
		t.Fatal()
	}

	contConfig := newTestContainerConfigNoop(contID)

	c, err := CreateContainer(p.id, contConfig)
	if c == nil || err != nil {
		t.Fatal()
	}

	contDir := filepath.Join(podDir, contID)
	_, err = os.Stat(contDir)
	if err != nil {
		t.Fatal()
	}

	c, err = StopContainer(p.id, contID)
	if c != nil || err == nil {
		t.Fatal()
	}
}

func TestEnterContainerNoopAgentSuccessful(t *testing.T) {
	contID := "100"
	config := newTestPodConfigNoop()

	p, err := CreatePod(config)
	if p == nil || err != nil {
		t.Fatal()
	}

	podDir := filepath.Join(configStoragePath, p.id)
	_, err = os.Stat(podDir)
	if err != nil {
		t.Fatal()
	}

	p, err = StartPod(p.id)
	if p == nil || err != nil {
		t.Fatal()
	}

	contConfig := newTestContainerConfigNoop(contID)

	c, err := CreateContainer(p.id, contConfig)
	if c == nil || err != nil {
		t.Fatal()
	}

	contDir := filepath.Join(podDir, contID)
	_, err = os.Stat(contDir)
	if err != nil {
		t.Fatal()
	}

	c, err = StartContainer(p.id, contID)
	if c == nil || err != nil {
		t.Fatal()
	}

	cmd := newBasicTestCmd()

	c, err = EnterContainer(p.id, contID, cmd)
	if c == nil || err != nil {
		t.Fatal()
	}
}

func TestEnterContainerHyperstartAgentSuccessful(t *testing.T) {
	contID := "100"
	config := newTestPodConfigHyperstartAgent()

	ctlSockPath, ioSockPath, mock := startMockHyperstart(t)

	hyperConfig := config.AgentConfig.(HyperConfig)
	hyperConfig.SockCtlName = ctlSockPath
	hyperConfig.SockTtyName = ioSockPath
	config.AgentConfig = hyperConfig

	p, err := CreatePod(config)
	if p == nil || err != nil {
		mock.Stop()
		t.Fatal()
	}

	podDir := filepath.Join(configStoragePath, p.id)
	_, err = os.Stat(podDir)
	if err != nil {
		mock.Stop()
		t.Fatal()
	}

	p, err = StartPod(p.id)
	if p == nil || err != nil {
		mock.Stop()
		t.Fatal()
	}

	mock.Stop()

	contConfig := newTestContainerConfigNoop(contID)

	c, err := CreateContainer(p.id, contConfig)
	if c == nil || err != nil {
		t.Fatal()
	}

	contDir := filepath.Join(podDir, contID)
	_, err = os.Stat(contDir)
	if err != nil {
		t.Fatal()
	}

	mock.Start()

	c, err = StartContainer(p.id, contID)
	if c == nil || err != nil {
		mock.Stop()
		t.Fatal()
	}

	mock.Stop()

	cmd := newBasicTestCmd()

	mock.Start()
	defer mock.Stop()

	c, err = EnterContainer(p.id, contID, cmd)
	if c == nil || err != nil {
		t.Fatal()
	}
}

func TestEnterContainerFailingNoPod(t *testing.T) {
	podDir := filepath.Join(configStoragePath, testPodID)
	contID := "100"
	os.RemoveAll(podDir)

	cmd := newBasicTestCmd()

	c, err := EnterContainer(testPodID, contID, cmd)
	if c != nil || err == nil {
		t.Fatal()
	}
}

func TestEnterContainerFailingNoContainer(t *testing.T) {
	contID := "100"
	config := newTestPodConfigNoop()

	p, err := CreatePod(config)
	if p == nil || err != nil {
		t.Fatal()
	}

	podDir := filepath.Join(configStoragePath, p.id)
	_, err = os.Stat(podDir)
	if err != nil {
		t.Fatal()
	}

	cmd := newBasicTestCmd()

	c, err := EnterContainer(p.id, contID, cmd)
	if c != nil || err == nil {
		t.Fatal()
	}
}

func TestEnterContainerFailingContNotStarted(t *testing.T) {
	contID := "100"
	config := newTestPodConfigNoop()

	p, err := CreatePod(config)
	if p == nil || err != nil {
		t.Fatal()
	}

	podDir := filepath.Join(configStoragePath, p.id)
	_, err = os.Stat(podDir)
	if err != nil {
		t.Fatal()
	}

	p, err = StartPod(p.id)
	if p == nil || err != nil {
		t.Fatal()
	}

	contConfig := newTestContainerConfigNoop(contID)

	c, err := CreateContainer(p.id, contConfig)
	if c == nil || err != nil {
		t.Fatal()
	}

	contDir := filepath.Join(podDir, contID)
	_, err = os.Stat(contDir)
	if err != nil {
		t.Fatal()
	}

	cmd := newBasicTestCmd()

	c, err = EnterContainer(p.id, contID, cmd)
	if c != nil || err == nil {
		t.Fatal()
	}
}

func TestStatusContainerSuccessful(t *testing.T) {
	contID := "100"
	config := newTestPodConfigNoop()

	p, err := CreatePod(config)
	if p == nil || err != nil {
		t.Fatal()
	}

	podDir := filepath.Join(configStoragePath, p.id)
	_, err = os.Stat(podDir)
	if err != nil {
		t.Fatal()
	}

	contConfig := newTestContainerConfigNoop(contID)

	c, err := CreateContainer(p.id, contConfig)
	if c == nil || err != nil {
		t.Fatal()
	}

	contDir := filepath.Join(podDir, contID)
	_, err = os.Stat(contDir)
	if err != nil {
		t.Fatal()
	}

	err = StatusContainer(p.id, contID)
	if err != nil {
		t.Fatal()
	}
}

func TestStatusContainerFailing(t *testing.T) {
	contID := "100"
	config := newTestPodConfigNoop()

	p, err := CreatePod(config)
	if p == nil || err != nil {
		t.Fatal()
	}

	podDir := filepath.Join(configStoragePath, p.id)
	_, err = os.Stat(podDir)
	if err != nil {
		t.Fatal()
	}

	err = StatusContainer(p.id, contID)
	if err == nil {
		t.Fatal()
	}
}
