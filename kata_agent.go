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
	"syscall"
)

type kataAgent struct {
}

func (k *kataAgent) init(pod *Pod, config interface{}) error {
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
	return nil
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
