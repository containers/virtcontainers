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

func testCreatePod(t *testing.T, id string,
	htype HypervisorType, hconfig HypervisorConfig, atype AgentType,
	containers []ContainerConfig, volumes []Volume) error {
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
		return fmt.Errorf("Could not create pod: %s", err)
	}

	if pod.id != id {
		return fmt.Errorf("Invalid ID")
	}

	return nil
}

func TestCreateEmtpyPod(t *testing.T) {
	err := testCreatePod(t, testPodID, MockHypervisor, HypervisorConfig{}, NoopAgentType, nil, nil)
	if err == nil {
		t.Fatalf("VirtContainers should not allow empty pods")
	}
}

func TestCreateEmtpyHypervisorPod(t *testing.T) {
	err := testCreatePod(t, testPodID, QemuHypervisor, HypervisorConfig{}, NoopAgentType, nil, nil)
	if err == nil {
		t.Fatalf("VirtContainers should not allow pods with empty hypervisors")
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
