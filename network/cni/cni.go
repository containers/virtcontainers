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

package cni

import (
	"fmt"
	"sort"

	"github.com/containernetworking/cni/libcni"
	"github.com/containernetworking/cni/pkg/types"
)

// CNI default values to find plugins and configurations.
const (
	LocalNetName  = "lo"
	DefNetName    = "net"
	PluginConfDir = "/etc/cni/net.d"
	PluginBinDir  = "/opt/cni/bin"
)

// NetworkPlugin is the CNI network plugin handler.
type NetworkPlugin struct {
	loNetwork  *cniNetwork
	defNetwork *cniNetwork
}

type cniNetwork struct {
	name          string
	networkConfig *libcni.NetworkConfig
	cniConfig     libcni.CNI
}

// NewNetworkPlugin initialize the CNI network plugin and returns
// a handler to it.
func NewNetworkPlugin() (*NetworkPlugin, error) {
	var err error

	plugin := &NetworkPlugin{}

	plugin.loNetwork, err = getLoNetwork()
	if err != nil {
		return nil, err
	}

	plugin.defNetwork, err = getDefNetwork()
	if err != nil {
		return nil, err
	}

	return plugin, nil
}

func getNetwork(defaultName string, local bool) (*cniNetwork, error) {
	confFiles, err := libcni.ConfFiles(PluginConfDir)
	if err != nil {
		return nil, err
	}

	if len(confFiles) == 0 {
		return nil, fmt.Errorf("Could not find networks in %s", PluginConfDir)
	}

	if local == true {
		sort.Sort(sort.Reverse(sort.StringSlice(confFiles)))
	} else {
		sort.Sort(sort.StringSlice(confFiles))
	}

	for _, confFile := range confFiles {
		conf, err := libcni.ConfFromFile(confFile)
		if err != nil {
			continue
		}

		cninet := &libcni.CNIConfig{
			Path: []string{PluginBinDir},
		}

		name := defaultName
		if conf.Network.Name != "" {
			name = conf.Network.Name
		}

		network := &cniNetwork{
			name:          name,
			networkConfig: conf,
			cniConfig:     cninet,
		}

		return network, nil
	}

	return nil, fmt.Errorf("No valid networks found in %s", PluginConfDir)
}

func getLoNetwork() (*cniNetwork, error) {
	return getNetwork(LocalNetName, true)
}

func getDefNetwork() (*cniNetwork, error) {
	return getNetwork(DefNetName, false)
}

func buildRuntimeConf(podID string, podNetNSPath string, ifName string) (*libcni.RuntimeConf, error) {
	rt := &libcni.RuntimeConf{
		ContainerID: podID,
		NetNS:       podNetNSPath,
		IfName:      ifName,
	}

	return rt, nil
}

// AddNetwork calls the CNI plugin to create a network between the host and the network namespace.
func (plugin *NetworkPlugin) AddNetwork(podID string, netNSPath string, ifName string) (*types.Result, error) {
	rt, err := buildRuntimeConf(podID, netNSPath, ifName)
	if err != nil {
		return nil, err
	}

	_, err = plugin.loNetwork.cniConfig.AddNetwork(plugin.loNetwork.networkConfig, rt)
	if err != nil {
		return nil, err
	}

	res, err := plugin.defNetwork.cniConfig.AddNetwork(plugin.defNetwork.networkConfig, rt)
	if err != nil {
		return nil, err
	}

	return res, nil
}

// RemoveNetwork calls the CNI plugin to remove a specific network previously created between
// the host and the network namespace.
func (plugin *NetworkPlugin) RemoveNetwork(podID string, netNSPath string, ifName string) error {
	rt, err := buildRuntimeConf(podID, netNSPath, ifName)
	if err != nil {
		return err
	}

	err = plugin.defNetwork.cniConfig.DelNetwork(plugin.defNetwork.networkConfig, rt)
	if err != nil {
		return err
	}

	err = plugin.loNetwork.cniConfig.DelNetwork(plugin.loNetwork.networkConfig, rt)
	if err != nil {
		return err
	}

	return nil
}
