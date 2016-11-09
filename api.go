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

	err = p.endSession()
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

	err = p.endSession()
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

	err = p.endSession()
	if err != nil {
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

	err = p.endSession()
	if err != nil {
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

	err = p.endSession()
	if err != nil {
		return nil, err
	}

	return p, nil
}

var listFormat = "%s\t%s\t%s\t%s\n"
var statusFormat = "%s\t%s\n"

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

// StatusPod is the virtcontainers pod status entry point.
func StatusPod(podID string) error {
	fs := filesystem{}

	w := tabwriter.NewWriter(os.Stdout, 2, 8, 1, '\t', 0)
	fmt.Fprintf(w, listFormat, "POD ID", "STATE", "HYPERVISOR", "AGENT")

	config, err := fs.fetchConfig(podID)
	if err != nil {
		return err
	}

	state, err := fs.fetchState(podID)
	if err != nil {
		return err
	}

	fmt.Fprintf(w, listFormat+"\n",
		podID, state.State, config.HypervisorType, config.AgentType)

	fmt.Fprintf(w, statusFormat, "CONTAINER ID", "STATE")

	for _, container := range config.Containers {
		path := fmt.Sprintf("%s/%s", podID, container.ID)
		contState, err := fs.fetchState(path)
		if err != nil {
			continue
		}

		fmt.Fprintf(w, statusFormat, container.ID, contState.State)
	}

	w.Flush()
	return nil
}

// CreateContainer is the virtcontainers container creation entry point.
// CreateContainer creates a container on a given pod.
func CreateContainer(podID string, containerConfig ContainerConfig) (*Container, error) {
	lockFile, err := lockPod(podID)
	if err != nil {
		return nil, err
	}
	defer unlockPod(lockFile)

	p, err := fetchPod(podID)
	if err != nil {
		return nil, err
	}

	// Create the container.
	c, err := createContainer(p, containerConfig)
	if err != nil {
		return nil, err
	}

	// Store it.
	err = c.storeContainer()
	if err != nil {
		return nil, err
	}

	// Update pod config.
	p.config.Containers = append(p.config.Containers, containerConfig)
	fs := filesystem{}
	err = storePodConfigUnlocked(*(p.config), fs)
	if err != nil {
		return nil, err
	}

	err = p.endSession()
	if err != nil {
		return nil, err
	}

	return c, nil
}

// DeleteContainer is the virtcontainers container deletion entry point.
// DeleteContainer deletes a Container from a Pod. If the container is running,
// it needs to be stopped first.
func DeleteContainer(podID, containerID string) (*Container, error) {
	lockFile, err := lockPod(podID)
	if err != nil {
		return nil, err
	}
	defer unlockPod(lockFile)

	p, err := fetchPod(podID)
	if err != nil {
		return nil, err
	}

	// Fetch the container.
	c, err := fetchContainer(p, containerID)
	if err != nil {
		return nil, err
	}

	// Delete it.
	err = c.delete()
	if err != nil {
		return nil, err
	}

	// Update pod config
	for idx, contConfig := range p.config.Containers {
		if contConfig.ID == containerID {
			p.config.Containers = append(p.config.Containers[:idx], p.config.Containers[idx+1:]...)
			break
		}
	}
	fs := filesystem{}
	err = storePodConfigUnlocked(*(p.config), fs)
	if err != nil {
		return nil, err
	}

	err = p.endSession()
	if err != nil {
		return nil, err
	}

	return c, nil
}

// StartContainer is the virtcontainers container starting entry point.
// StartContainer starts an already created container.
func StartContainer(podID, containerID string) (*Container, error) {
	lockFile, err := lockPod(podID)
	if err != nil {
		return nil, err
	}
	defer unlockPod(lockFile)

	p, err := fetchPod(podID)
	if err != nil {
		return nil, err
	}

	// Fetch the container.
	c, err := fetchContainer(p, containerID)
	if err != nil {
		return nil, err
	}

	// Start it.
	err = c.start()
	if err != nil {
		c.delete()
		return nil, err
	}

	err = p.endSession()
	if err != nil {
		return nil, err
	}

	return c, nil
}

// StopContainer is the virtcontainers container stopping entry point.
// StopContainer stops an already running container.
func StopContainer(podID, containerID string) (*Container, error) {
	lockFile, err := lockPod(podID)
	if err != nil {
		return nil, err
	}
	defer unlockPod(lockFile)

	p, err := fetchPod(podID)
	if err != nil {
		return nil, err
	}

	// Fetch the container.
	c, err := fetchContainer(p, containerID)
	if err != nil {
		return nil, err
	}

	// Stop it.
	err = c.stop()
	if err != nil {
		c.delete()
		return nil, err
	}

	err = p.endSession()
	if err != nil {
		return nil, err
	}

	return c, nil
}

// EnterContainer is the virtcontainers container command execution entry point.
// EnterContainer enters an already running container and runs a given command.
func EnterContainer(podID, containerID string, cmd Cmd) (*Container, error) {
	lockFile, err := lockPod(podID)
	if err != nil {
		return nil, err
	}
	defer unlockPod(lockFile)

	p, err := fetchPod(podID)
	if err != nil {
		return nil, err
	}

	// Fetch the container.
	c, err := fetchContainer(p, containerID)
	if err != nil {
		return nil, err
	}

	// Enter it.
	err = c.enter(cmd)
	if err != nil {
		return nil, err
	}

	err = p.endSession()
	if err != nil {
		return nil, err
	}

	return c, nil
}

// ContainerStatus is the virtcontainers container status entry point.
// ContainerStatus returns a detailed container status.
func ContainerStatus(podID, containerID string) error {
	fs := filesystem{}

	w := tabwriter.NewWriter(os.Stdout, 2, 8, 1, '\t', 0)

	cPath := filepath.Join(podID, containerID)
	state, err := fs.fetchState(cPath)
	if err != nil {
		return err
	}

	fmt.Fprintf(w, statusFormat, "CONTAINER ID", "STATE")
	fmt.Fprintf(w, statusFormat, containerID, state.State)

	w.Flush()

	return nil
}
