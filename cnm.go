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
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containers/virtcontainers/pkg/uuid"
	"github.com/sirupsen/logrus"
)

// cnm is a network implementation for the CNM plugin.
type cnm struct {
	config NetworkConfig
}

func cnmLogger() *logrus.Entry {
	return virtLog.WithField("subsystem", "cnm")
}

func (n *cnm) createEndpointsFromScan(networkNSPath string) ([]Endpoint, error) {
	var endpoints []Endpoint

	netIfaces, err := getIfacesFromNetNs(networkNSPath)
	if err != nil {
		return []Endpoint{}, err
	}

	uniqueID := uuid.Generate().String()

	idx := 0
	for _, netIface := range netIfaces {
		var endpoint Endpoint

		if netIface.Iface.Name == "lo" {
			continue
		}

		err := doNetNS(networkNSPath, func(_ ns.NetNS) error {
			// Check if interface is a physical interface. Do not create
			// tap interface/bridge if it is.
			isPhysical, err := isPhysicalIface(netIface.Iface.Name)
			if err != nil {
				return err
			}

			if isPhysical {
				cnmLogger().WithField("interface", netIface.Iface.Name).Info("Physical network interface found")
				endpoint, err = createPhysicalEndpoint(netIface.Iface.Name)
			} else {
				endpoint, err = createVirtualNetworkEndpoint(idx, uniqueID, netIface.Iface.Name)
			}

			return err
		})

		if err != nil {
			return []Endpoint{}, err
		}

		routes, err := getNetIfaceRoutesWithinNetNs(networkNSPath, netIface.Iface.Name)
		if err != nil {
			return []Endpoint{}, err
		}

		properties := NetworkInfo{
			Iface:  netIface,
			Routes: routes,
		}

		endpoint.SetProperties(properties)
		endpoints = append(endpoints, endpoint)

		idx++
	}

	return endpoints, nil
}

// init initializes the network, setting a new network namespace for the CNM network.
func (n *cnm) init(config NetworkConfig) (string, bool, error) {
	return initNetworkCommon(config)
}

// run runs a callback in the specified network namespace.
func (n *cnm) run(networkNSPath string, cb func() error) error {
	return runNetworkCommon(networkNSPath, cb)
}

// add adds all needed interfaces inside the network namespace for the CNM network.
func (n *cnm) add(pod Pod, config NetworkConfig, netNsPath string, netNsCreated bool) (NetworkNamespace, error) {
	endpoints, err := n.createEndpointsFromScan(netNsPath)
	if err != nil {
		return NetworkNamespace{}, err
	}

	networkNS := NetworkNamespace{
		NetNsPath:    netNsPath,
		NetNsCreated: netNsCreated,
		Endpoints:    endpoints,
	}

	if err := addNetworkCommon(pod, &networkNS); err != nil {
		return NetworkNamespace{}, err
	}

	return networkNS, nil
}

// remove unbridges and deletes TAP interfaces. It also removes virtual network
// interfaces and deletes the network namespace for the CNM network.
func (n *cnm) remove(pod Pod, networkNS NetworkNamespace) error {
	if err := removeNetworkCommon(networkNS); err != nil {
		return err
	}

	return deleteNetNS(networkNS.NetNsPath, true)
}
