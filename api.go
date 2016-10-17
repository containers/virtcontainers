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
	"text/tabwriter"
)

// CreatePod is the virtcontainers pod creation entry point.
// CreatePod creates a pod and its containers. It does not start them.
func CreatePod(podConfig PodConfig) (*Pod, error) {
	// Create the pod.
	p, err := createPod(podConfig)
	if err != nil {
		return nil, err
	}

	// Store it.
	err = p.storePod()
	if err != nil {
		return nil, err
	}

	return p, nil
}

// DeletePod is the virtcontainers pod deletion entry point.
// DeletePod will stop an already running container and then delete it.
func DeletePod(podID string) (*Pod, error) {
	// Fetch the pod from storage and create it.
	p, err := fetchPod(podID)
	if err != nil {
		return nil, err
	}

	// Delete it.
	err = p.delete()
	if err != nil {
		return nil, err
	}

	return p, nil
}

// StartPod is the virtcontainers pod starting entry point.
// StartPod will talk to the given hypervisor to start an existing
// pod and all its containers.
// It returns the pod ID.
func StartPod(podID string) (*Pod, error) {
	// Fetch the pod from storage and create it.
	p, err := fetchPod(podID)
	if err != nil {
		return nil, err
	}

	// Start it.
	err = p.start()
	if err != nil {
		p.delete()
		return nil, err
	}

	return p, nil
}

// StopPod is the virtcontainers pod stopping entry point.
// StopPod will talk to the given agent to stop an existing pod and destroy all containers within that pod.
func StopPod(podID string) (*Pod, error) {
	// Fetch the pod from storage and create it.
	p, err := fetchPod(podID)
	if err != nil {
		return nil, err
	}

	// Stop it.
	err = p.stop()
	if err != nil {
		p.delete()
		return nil, err
	}

	return p, nil
}

// RunPod is the virtcontainers pod running entry point.
// RunPod creates a pod and its containers and then it starts them.
func RunPod(podConfig PodConfig) (*Pod, error) {
	// Create the pod.
	p, err := createPod(podConfig)
	if err != nil {
		return nil, err
	}

	// Store it.
	err = p.storePod()
	if err != nil {
		return nil, err
	}

	// Start it.
	err = p.start()
	if err != nil {
		p.delete()
		return nil, err
	}

	return p, nil
}

var listFormat = "%s\t%s\t%s\t%s\n"

// ListPod is the virtcontainers pod listing entry point.
func ListPod() error {
	dir, err := os.Open(configStoragePath)
	if err != nil {
		return err
	}

	defer dir.Close()

	pods, err := dir.Readdirnames(0)
	if err != nil {
		return err
	}

	fs := filesystem{}

	w := tabwriter.NewWriter(os.Stdout, 2, 8, 1, '\t', 0)
	fmt.Fprintf(w, listFormat, "POD ID", "STATE", "HYPERVISOR", "AGENT")

	for _, p := range pods {
		config, err := fs.fetchConfig(p)
		if err != nil {
			continue
		}

		state, err := fs.fetchState(p)
		if err != nil {
			continue
		}

		fmt.Fprintf(w, listFormat,
			config.ID, state.State, config.HypervisorType, config.AgentType)
	}

	w.Flush()
	return nil
}
