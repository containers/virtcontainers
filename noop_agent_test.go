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
	"testing"
)

func TestNoopAgentInit(t *testing.T) {
	n := &noopAgent{}
	pod := &Pod{}

	err := n.init(pod, nil)
	if err != nil {
		t.Fatal(err)
	}
}

func TestNoopAgentStartAgent(t *testing.T) {
	n := &noopAgent{}

	err := n.startAgent()
	if err != nil {
		t.Fatal(err)
	}
}

func TestNoopAgentExec(t *testing.T) {
	n := &noopAgent{}
	pod := Pod{}
	container := Container{}
	cmd := Cmd{}

	if _, err := n.exec(pod, container, cmd); err != nil {
		t.Fatal(err)
	}
}

func TestNoopAgentStartPod(t *testing.T) {
	n := &noopAgent{}
	podConfig := PodConfig{}

	err := n.startPod(podConfig)
	if err != nil {
		t.Fatal(err)
	}
}

func TestNoopAgentStopPod(t *testing.T) {
	n := &noopAgent{}
	pod := Pod{}

	err := n.stopPod(pod)
	if err != nil {
		t.Fatal(err)
	}
}

func TestNoopAgentStopAgent(t *testing.T) {
	n := &noopAgent{}

	err := n.stopAgent()
	if err != nil {
		t.Fatal(err)
	}
}

func TestNoopAgentCreateContainer(t *testing.T) {
	n := &noopAgent{}
	contConfig := ContainerConfig{}

	err := n.createContainer(contConfig)
	if err != nil {
		t.Fatal(err)
	}
}

func TestNoopAgentStartContainer(t *testing.T) {
	n := &noopAgent{}
	pod := Pod{}
	contConfig := ContainerConfig{}

	err := n.startContainer(pod, contConfig)
	if err != nil {
		t.Fatal(err)
	}
}

func TestNoopAgentStopContainer(t *testing.T) {
	n := &noopAgent{}
	pod := Pod{}
	container := Container{}

	err := n.stopContainer(pod, container)
	if err != nil {
		t.Fatal(err)
	}
}
