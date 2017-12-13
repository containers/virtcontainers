//
// Copyright (c) 2017 Intel Corporation
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

	kataclient "github.com/kata-containers/agent/protocols/client"
)

// KataAgentConfig is a structure storing information needed
// to reach the Kata Containers agent.
type KataAgentConfig struct {
	GRPCSocket string
	Volumes    []Volume
	VMSocket   Socket
}

func (c *KataAgentConfig) validate(pod *Pod) bool {
	return true
}

type kataAgent struct {
	config KataAgentConfig

	client *kataclient.AgentClient
}

func (k *kataAgent) init(pod *Pod, config interface{}) error {
	switch c := config.(type) {
	case KataAgentConfig:
		if c.validate(pod) == false {
			return fmt.Errorf("Invalid Kata agent configuration: %v", c)
		}
		k.config = c
	default:
		return fmt.Errorf("Invalid config type")
	}

	// Override pod agent configuration
	pod.config.AgentConfig = k.config

	client, err := kataclient.NewAgentClient(k.config.GRPCSocket)
	if err != nil {
		return err
	}

	k.client = client

	return nil
}

func (k *kataAgent) capabilities() capabilities {
	return capabilities{}
}

func (k *kataAgent) createPod(pod *Pod) error {
	for _, volume := range k.config.Volumes {
		err := pod.hypervisor.addDevice(volume, fsDev)
		if err != nil {
			return err
		}
	}

	// TODO Look at the grpc scheme to understand if we want
	// a serial or a vsock socket.
	err := pod.hypervisor.addDevice(k.config.VMSocket, serialPortDev)
	if err != nil {
		return err
	}

	// Adding the shared volume.
	// This volume contains all bind mounted container bundles.
	sharedVolume := Volume{
		MountTag: mountTag,
		HostPath: filepath.Join(defaultSharedDir, pod.id),
	}

	if err := os.MkdirAll(sharedVolume.HostPath, dirMode); err != nil {
		return err
	}

	return pod.hypervisor.addDevice(sharedVolume, fsDev)
}

func (k *kataAgent) exec(pod *Pod, c Container, process Process, cmd Cmd) error {
	return nil
}

func (k *kataAgent) startPod(pod Pod) error {
	return nil
}

func (k *kataAgent) stopPod(pod Pod) error {
	return nil
}

func (k *kataAgent) createContainer(pod *Pod, c *Container) error {
	return nil
}

func (k *kataAgent) startContainer(pod Pod, c Container) error {
	return nil
}

func (k *kataAgent) stopContainer(pod Pod, c Container) error {
	return nil
}

func (k *kataAgent) killContainer(pod Pod, c Container, signal syscall.Signal, all bool) error {
	return nil
}

func (k *kataAgent) processListContainer(pod Pod, c Container, options ProcessListOptions) (ProcessList, error) {
	return nil, nil
}
