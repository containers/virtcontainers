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
	"github.com/containernetworking/cni/pkg/ns"
	cniPlugin "github.com/containers/virtcontainers/network/cni"
	"github.com/golang/glog"
)

// cni is a network implementation for the CNI plugin.
type cni struct{}

func (n *cni) addVirtInterfaces(networkNS *NetworkNamespace) error {
	netPlugin, err := cniPlugin.NewNetworkPlugin()
	if err != nil {
		return err
	}

	for idx, endpoint := range networkNS.Endpoints {
		result, err := netPlugin.AddNetwork(endpoint.NetPair.ID, networkNS.NetNsPath, endpoint.NetPair.VirtIface.Name)
		if err != nil {
			return err
		}

		networkNS.Endpoints[idx].Properties = *result

		glog.Infof("AddNetwork results %v\n", *result)
	}

	return nil
}

func (n *cni) deleteVirtInterfaces(networkNS NetworkNamespace) error {
	netPlugin, err := cniPlugin.NewNetworkPlugin()
	if err != nil {
		return err
	}

	for _, endpoint := range networkNS.Endpoints {
		err := netPlugin.RemoveNetwork(endpoint.NetPair.ID, networkNS.NetNsPath, endpoint.NetPair.VirtIface.Name)
		if err != nil {
			return err
		}
	}

	return nil
}

// add creates a new network namespace and its virtual network interfaces,
// and it creates and bridges TAP interfaces for the CNI network.
func (n *cni) add(config *NetworkConfig) (NetworkNamespace, error) {
	var err error

	if config.NetNSPath == "" {
		path, err := createNetNS()
		if err != nil {
			return NetworkNamespace{}, err
		}

		config.NetNSPath = path
	}

	endpoints, err := createNetworkEndpoints(config.NumInterfaces)
	if err != nil {
		return NetworkNamespace{}, err
	}

	networkNS := NetworkNamespace{
		NetNsPath: config.NetNSPath,
		Endpoints: endpoints,
	}

	err = n.addVirtInterfaces(&networkNS)
	if err != nil {
		return NetworkNamespace{}, err
	}

	err = setNetNS(config.NetNSPath)
	if err != nil {
		return NetworkNamespace{}, err
	}

	for _, endpoint := range networkNS.Endpoints {
		err = bridgeNetworkPair(endpoint.NetPair)
		if err != nil {
			return NetworkNamespace{}, err
		}
	}

	return networkNS, nil
}

// join switches the current process to the specified network namespace
// for the CNI network.
func (n *cni) join(networkNS NetworkNamespace) error {
	err := setNetNS(networkNS.NetNsPath)
	if err != nil {
		return err
	}

	return nil
}

// remove unbridges and deletes TAP interfaces. It also removes virtual network
// interfaces and deletes the network namespace for the CNI network.
func (n *cni) remove(networkNS NetworkNamespace) error {
	err := doNetNS(networkNS.NetNsPath, func(_ ns.NetNS) error {
		for _, endpoint := range networkNS.Endpoints {
			err := unBridgeNetworkPair(endpoint.NetPair)
			if err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return err
	}

	err = n.deleteVirtInterfaces(networkNS)
	if err != nil {
		return err
	}

	err = deleteNetNS(networkNS.NetNsPath, true)
	if err != nil {
		return err
	}

	return nil
}
