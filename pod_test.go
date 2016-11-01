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
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

const testPodID = "7f49d00d-1995-4156-8c79-5f5ab24ce138"
const testDir = "/tmp/virtcontainers/"
const testKernel = "kernel"
const testImage = "image"
const testHypervisor = "hypervisor"

func newHypervisorConfig(kernelParams []Param, hParams []Param) HypervisorConfig {
	return HypervisorConfig{
		KernelPath:       filepath.Join(testDir, testKernel),
		ImagePath:        filepath.Join(testDir, testImage),
		HypervisorPath:   filepath.Join(testDir, testHypervisor),
		KernelParams:     kernelParams,
		HypervisorParams: hParams,
	}

}

func testCreatePod(t *testing.T, id string,
	htype HypervisorType, hconfig HypervisorConfig, atype AgentType,
	containers []ContainerConfig, volumes []Volume) (*Pod, error) {
	config := PodConfig{
		ID:               id,
		HypervisorType:   htype,
		HypervisorConfig: hconfig,
		AgentType:        atype,
		Volumes:          volumes,
		Containers:       containers,
	}

	pod, err := createPod(config)
	if err != nil {
		return nil, fmt.Errorf("Could not create pod: %s", err)
	}

	if pod.id == "" {
		return pod, fmt.Errorf("Invalid empty pod ID")
	}

	if id != "" && pod.id != id {
		return pod, fmt.Errorf("Invalid ID %s vs %s", id, pod.id)
	}

	return pod, nil
}

func TestCreateEmtpyPod(t *testing.T) {
	_, err := testCreatePod(t, testPodID, MockHypervisor, HypervisorConfig{}, NoopAgentType, nil, nil)
	if err == nil {
		t.Fatalf("VirtContainers should not allow empty pods")
	}
}

func TestCreateEmtpyHypervisorPod(t *testing.T) {
	_, err := testCreatePod(t, testPodID, QemuHypervisor, HypervisorConfig{}, NoopAgentType, nil, nil)
	if err == nil {
		t.Fatalf("VirtContainers should not allow pods with empty hypervisors")
	}
}

func TestCreateMockPod(t *testing.T) {
	hConfig := newHypervisorConfig(nil, nil)

	_, err := testCreatePod(t, testPodID, MockHypervisor, hConfig, NoopAgentType, nil, nil)
	if err != nil {
		t.Fatalf("Could not create mock pod")
	}
}

func TestCreatePodEmtpyID(t *testing.T) {
	hConfig := newHypervisorConfig(nil, nil)

	p, err := testCreatePod(t, "", MockHypervisor, hConfig, NoopAgentType, nil, nil)
	if err != nil {
		t.Fatalf("Could not create mock pod")
	}

	t.Logf("Got new ID %s", p.id)
}

func testPodStateTransition(t *testing.T, state stateString, newState stateString) error {
	hConfig := newHypervisorConfig(nil, nil)

	p, err := testCreatePod(t, testPodID, MockHypervisor, hConfig, NoopAgentType, nil, nil)
	if err != nil {
		return fmt.Errorf("Could not create mock pod")
	}

	p.state = State{
		State: state,
	}

	return p.state.validTransition(state, newState)
}

func TestPodStateReadyRunning(t *testing.T) {
	err := testPodStateTransition(t, podReady, podRunning)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPodStateRunningPaused(t *testing.T) {
	err := testPodStateTransition(t, podRunning, podPaused)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPodStatePausedRunning(t *testing.T) {
	err := testPodStateTransition(t, podPaused, podRunning)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPodStateRunningReady(t *testing.T) {
	err := testPodStateTransition(t, podRunning, podReady)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPodStateReadyPaused(t *testing.T) {
	err := testPodStateTransition(t, podReady, podPaused)
	if err == nil {
		t.Fatal("Invalid transition from Ready to Paused")
	}
}

func TestPodStatePausedReady(t *testing.T) {
	err := testPodStateTransition(t, podPaused, podReady)
	if err == nil {
		t.Fatal("Invalid transition from Ready to Paused")
	}
}

func testPodDir(t *testing.T, resource podResource, expected string) error {
	dir, err := podDir(testPodID, resource)
	if err != nil {
		return err
	}

	if dir != expected {
		return fmt.Errorf("Unexpected pod directory %s vs %s", dir, expected)
	}

	return nil
}

var podDirConfig = filepath.Join(configStoragePath, testPodID)

func TestPodDirConfig(t *testing.T) {
	err := testPodDir(t, configFileType, podDirConfig)
	if err != nil {
		t.Fatal(err)
	}
}

var podDirState = filepath.Join(runStoragePath, testPodID)

func TestPodDirState(t *testing.T) {
	err := testPodDir(t, stateFileType, podDirState)
	if err != nil {
		t.Fatal(err)
	}
}

var podDirLock = filepath.Join(runStoragePath, testPodID)

func TestPodDirLock(t *testing.T) {
	err := testPodDir(t, lockFileType, podDirLock)
	if err != nil {
		t.Fatal(err)
	}
}

func TestPodDirNegative(t *testing.T) {
	_, err := podDir("", lockFileType)
	if err == nil {
		t.Fatal("Empty pod IDs should not be allowed")
	}
}

func TestMain(m *testing.M) {
	flag.Parse()

	err := os.MkdirAll(testDir, os.ModeDir)
	if err != nil {
		fmt.Printf("Could not create test directories\n")
		os.Exit(1)
	}

	defer os.RemoveAll(testDir)

	_, err = os.Create(filepath.Join(testDir, testKernel))
	if err != nil {
		fmt.Printf("Could not create test kernel\n")
		os.Exit(1)
	}

	_, err = os.Create(filepath.Join(testDir, testImage))
	if err != nil {
		fmt.Printf("Could not create test image\n")
		os.Exit(1)
	}

	_, err = os.Create(filepath.Join(testDir, testHypervisor))
	if err != nil {
		fmt.Printf("Could not create test hypervisor\n")
		os.Exit(1)
	}

	os.Exit(m.Run())
}
