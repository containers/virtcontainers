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

	"github.com/mitchellh/mapstructure"
)

// AgentType describes the type of guest agent a Pod should run.
type AgentType string

const (
	// NoopAgentType is the No-Op agent.
	NoopAgentType AgentType = "noop"

	// SSHdAgent is the SSH daemon agent.
	SSHdAgent = "sshd"

	// HyperstartAgent is the Hyper hyperstart agent.
	HyperstartAgent = "hyperstart"
)

// Set sets an agent type based on the input string.
func (agentType *AgentType) Set(value string) error {
	switch value {
	case "noop":
		*agentType = NoopAgentType
		return nil
	case "sshd":
		*agentType = SSHdAgent
		return nil
	case "hyperstart":
		*agentType = HyperstartAgent
		return nil
	default:
		return fmt.Errorf("Unknown agent type %s", value)
	}
}

// String converts an agent type to a string.
func (agentType *AgentType) String() string {
	switch *agentType {
	case NoopAgentType:
		return string(NoopAgentType)
	case SSHdAgent:
		return string(SSHdAgent)
	case HyperstartAgent:
		return string(HyperstartAgent)
	default:
		return ""
	}
}

// newAgent returns an agent from an agent type.
func newAgent(agentType AgentType) (agent, error) {
	switch agentType {
	case NoopAgentType:
		return &noopAgent{}, nil
	case SSHdAgent:
		return &sshd{}, nil
	case HyperstartAgent:
		return &hyper{}, nil
	default:
		return &noopAgent{}, nil
	}
}

// newAgentConfig returns an agent config from a generic PodConfig interface.
func newAgentConfig(config PodConfig) interface{} {
	switch config.AgentType {
	case NoopAgentType:
		return nil
	case SSHdAgent:
		var sshdConfig SshdConfig
		err := mapstructure.Decode(config.AgentConfig, &sshdConfig)
		if err != nil {
			return err
		}
		return sshdConfig
	case HyperstartAgent:
		var hyperConfig HyperConfig
		err := mapstructure.Decode(config.AgentConfig, &hyperConfig)
		if err != nil {
			return err
		}
		return hyperConfig
	default:
		return nil
	}
}

// agent is the virtcontainers agent interface.
// Agents are running in the guest VM and handling
// communications between the host and guest.
type agent interface {
	// init is used to pass agent specific configuration to the agent implementation.
	// agent implementations also will typically start listening for agent events from
	// init().
	// After init() is called, agent implementations should be initialized and ready
	// to handle all other Agent interface methods.
	init(config interface{}, hypervisor hypervisor) error

	// start will start the agent on the host.
	start() error

	// exec will tell the agent to run a command in an already running container.
	exec(podID string, contID string, cmd Cmd) error

	// startPod will tell the agent to start all containers related to the Pod.
	startPod(config PodConfig) error

	// stopPod will tell the agent to stop all containers related to the Pod.
	stopPod(config PodConfig) error

	// stop will stop the agent on the host.
	stop() error
}
