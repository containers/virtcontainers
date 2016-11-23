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
)

func newTestPodConfigNoop() PodConfig {
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

	// Define the container command and bundle.
	container := ContainerConfig{
		ID:     "1",
		RootFs: filepath.Join(testDir, testBundle),
		Cmd:    cmd,
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

func TestCreatePodSuccessful(t *testing.T) {
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

func TestCreatePodFailing(t *testing.T) {
	config := PodConfig{}

	p, err := CreatePod(config)
	if p != nil || err == nil {
		t.Fatal()
	}
}

func TestDeletePodSuccessful(t *testing.T) {
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

func TestDeletePodFailing(t *testing.T) {
	podDir := filepath.Join(configStoragePath, testPodID)
	os.Remove(podDir)

	p, err := DeletePod(testPodID)
	if p != nil || err == nil {
		t.Fatal()
	}
}

func TestStartPodSuccessful(t *testing.T) {
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

func TestStartPodFailing(t *testing.T) {
	podDir := filepath.Join(configStoragePath, testPodID)
	os.Remove(podDir)

	p, err := StartPod(testPodID)
	if p != nil || err == nil {
		t.Fatal()
	}
}

func TestStopPodSuccessful(t *testing.T) {
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

func TestStopPodFailing(t *testing.T) {
	podDir := filepath.Join(configStoragePath, testPodID)
	os.Remove(podDir)

	p, err := StopPod(testPodID)
	if p != nil || err == nil {
		t.Fatal()
	}
}

func TestRunPodSuccessful(t *testing.T) {
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
