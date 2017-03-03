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

	"github.com/mitchellh/mapstructure"
)

// ProxyType describes a proxy type.
type ProxyType string

const (
	// CCProxyType is the ccProxy.
	CCProxyType ProxyType = "ccProxy"

	// NoopProxyType is the noopProxy.
	NoopProxyType ProxyType = "noopProxy"
)

// Set sets a proxy type based on the input string.
func (pType *ProxyType) Set(value string) error {
	switch value {
	case "noopProxy":
		*pType = NoopProxyType
		return nil
	case "ccProxy":
		*pType = CCProxyType
		return nil
	default:
		return fmt.Errorf("Unknown proxy type %s", value)
	}
}

// String converts a proxy type to a string.
func (pType *ProxyType) String() string {
	switch *pType {
	case NoopProxyType:
		return string(NoopProxyType)
	case CCProxyType:
		return string(CCProxyType)
	default:
		return ""
	}
}

// newProxy returns a proxy from a proxy type.
func newProxy(pType ProxyType) (proxy, error) {
	switch pType {
	case NoopProxyType:
		return &noopProxy{}, nil
	case CCProxyType:
		return &ccProxy{}, nil
	default:
		return &noopProxy{}, nil
	}
}

// newProxyConfig returns a proxy config from a generic PodConfig interface.
func newProxyConfig(config PodConfig) interface{} {
	switch config.ProxyType {
	case NoopProxyType:
		return nil
	case CCProxyType:
		var ccConfig CCProxyConfig
		err := mapstructure.Decode(config.ProxyConfig, &ccConfig)
		if err != nil {
			return err
		}
		return ccConfig
	default:
		return nil
	}
}

// ProxyInfo holds the token and url returned by the proxy.
// Each ProxyInfo relates to a process running inside a container.
type ProxyInfo struct {
	Token string
	URL   string

	// Keep for legacy, will be removed when new proxy is ready.
	StdioID  uint64
	StderrID uint64
}

// proxy is the virtcontainers proxy interface.
type proxy interface {
	// register connects and registers the proxy to the given VM.
	// It also returns information related to containers workloads.
	register(pod Pod, reuseConnection bool) ([]ProxyInfo, error)

	// unregister unregisters and disconnects the proxy from the given VM.
	unregister(pod Pod) error

	// connect gets the proxy a handle to a previously registered VM.
	// It also returns information related to containers workloads.
	connect(pod Pod, reuseConnection bool) (ProxyInfo, error)

	// disconnect disconnects from the proxy.
	disconnect() error

	// sendCmd sends a command to the agent inside the VM through the proxy.
	sendCmd(cmd interface{}) (interface{}, error)
}
