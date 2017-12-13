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
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	kataclient "github.com/kata-containers/agent/protocols/client"
	"github.com/kata-containers/agent/protocols/grpc"
)

var errorMissingGRPClient = fmt.Errorf("Missing gRPC client")
var defaultHostSharedDir = "/tmp/kata-containers/shared/pods/"
var defaultGuestSharedDir = "/tmp/kata-containers/shared/pods/"
var mountGuest9pTag = "kataShared"
var type9pFs = "9p"

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

func (k *kataAgent) vmURL() (string, error) {
	return "", nil
}

func (k *kataAgent) setProxyURL(url string) error {
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
		MountTag: mountGuest9pTag,
		HostPath: filepath.Join(defaultHostSharedDir, pod.id),
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
	if k.client == nil {
		return errorMissingGRPClient
	}

	hostname := pod.config.Hostname
	if len(hostname) > maxHostnameLen {
		hostname = hostname[:maxHostnameLen]
	}

	// We mount the shared directory in a predefined location
	// in the guest.
	// This is where at least some of the host config files
	// (resolv.conf, etc...) and potentially all container
	// rootfs will reside.
	sharedVolume := &grpc.Storage{
		Source:     mountGuest9pTag,
		MountPoint: defaultGuestSharedDir,
		Fstype:     type9pFs,
		Options:    []string{"trans=virtio", "nodev"},
	}

	req := &grpc.CreateSandboxRequest{
		Hostname:     hostname,
		Storages:     []*grpc.Storage{sharedVolume},
		SandboxPidns: true,
	}
	_, err := k.client.CreateSandbox(context.Background(), req)
	return err
}

func (k *kataAgent) stopPod(pod Pod) error {
	if k.client == nil {
		return errorMissingGRPClient
	}

	req := &grpc.DestroySandboxRequest{}
	_, err := k.client.DestroySandbox(context.Background(), req)
	return err
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
