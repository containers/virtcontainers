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
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/01org/ciao/ssntp/uuid"
	"github.com/containernetworking/cni/pkg/ns"
	types "github.com/containernetworking/cni/pkg/types/current"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// NetworkInterface defines a network interface.
type NetworkInterface struct {
	Name     string
	HardAddr string
}

// NetworkInterfacePair defines a pair between TAP and virtual network interfaces.
type NetworkInterfacePair struct {
	ID        string
	Name      string
	VirtIface NetworkInterface
	TAPIface  NetworkInterface
}

// NetworkConfig is the network configuration related to a network.
type NetworkConfig struct {
	NetNSPath     string
	NumInterfaces int
}

// Endpoint gathers a network pair and its properties.
type Endpoint struct {
	NetPair    NetworkInterfacePair
	Properties types.Result
}

// NetworkNamespace contains all data related to its network namespace.
type NetworkNamespace struct {
	NetNsPath string
	Endpoints []Endpoint
}

// NetworkModel describes the type of network specification.
type NetworkModel string

const (
	// NoopNetworkModel is the No-Op network.
	NoopNetworkModel NetworkModel = "noop"

	// CNINetworkModel is the CNI network.
	CNINetworkModel NetworkModel = "CNI"

	// CNMNetworkModel is the CNM network.
	CNMNetworkModel NetworkModel = "CNM"
)

// Set sets a network type based on the input string.
func (networkType *NetworkModel) Set(value string) error {
	switch value {
	case "noop":
		*networkType = NoopNetworkModel
		return nil
	case "CNI":
		*networkType = CNINetworkModel
		return nil
	case "CNM":
		*networkType = CNMNetworkModel
		return nil
	default:
		return fmt.Errorf("Unknown network type %s", value)
	}
}

// String converts a network type to a string.
func (networkType *NetworkModel) String() string {
	switch *networkType {
	case NoopNetworkModel:
		return string(NoopNetworkModel)
	case CNINetworkModel:
		return string(CNINetworkModel)
	case CNMNetworkModel:
		return string(CNMNetworkModel)
	default:
		return ""
	}
}

// newNetwork returns a network from a network type.
func newNetwork(networkType NetworkModel) network {
	switch networkType {
	case NoopNetworkModel:
		return &noopNetwork{}
	case CNINetworkModel:
		return &cni{}
	case CNMNetworkModel:
		return &cnm{}
	default:
		return &noopNetwork{}
	}
}

func createTAP(netHandle *netlink.Handle, tapName string) (netlink.Link, error) {
	tap := &netlink.Tuntap{
		LinkAttrs: netlink.LinkAttrs{Name: tapName},
		Mode:      netlink.TUNTAP_MODE_TAP,
	}

	if err := netHandle.LinkAdd(tap); err != nil {
		return nil, fmt.Errorf("LinkAdd() failed for TAP name %s: %s", tapName, err)
	}

	link, err := netHandle.LinkByName(tapName)
	if err != nil {
		return nil, fmt.Errorf("LinkByName() failed for TAP name %s: %s", tapName, err)
	}

	tapLink, ok := link.(*netlink.GenericLink)
	if ok == false {
		return nil, fmt.Errorf("Incorrect link type %s", link.Type())
	}

	return tapLink, nil
}

func createBridge(netHandle *netlink.Handle, bridgeName string) (netlink.Link, error) {
	bridge := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: bridgeName}}

	if err := netHandle.LinkAdd(bridge); err != nil {
		return nil, fmt.Errorf("LinkAdd() failed for bridge name %s: %s", bridgeName, err)
	}

	link, err := netHandle.LinkByName(bridgeName)
	if err != nil {
		return nil, fmt.Errorf("LinkByName() failed for bridge name %s: %s", bridgeName, err)
	}

	bridgeLink, ok := link.(*netlink.Bridge)
	if ok == false {
		return nil, fmt.Errorf("Incorrect link type %s", link.Type())
	}

	return bridgeLink, nil
}

func getVeth(netHandle *netlink.Handle, vethName string) (netlink.Link, error) {
	link, err := netHandle.LinkByName(vethName)
	if err != nil {
		return nil, fmt.Errorf("LinkByName() failed for veth name %s: %s", vethName, err)
	}

	vethLink, ok := link.(*netlink.Veth)
	if ok == false {
		return nil, fmt.Errorf("Incorrect link type %s", link.Type())
	}

	return vethLink, nil
}

func getTAP(netHandle *netlink.Handle, tapName string) (netlink.Link, error) {
	link, err := netHandle.LinkByName(tapName)
	if err != nil {
		return nil, fmt.Errorf("LinkByName() failed for TAP name %s: %s", tapName, err)
	}

	tapLink, ok := link.(*netlink.GenericLink)
	if ok == false {
		return nil, fmt.Errorf("Incorrect link type %s", link.Type())
	}

	return tapLink, nil
}

func getBridge(netHandle *netlink.Handle, bridgeName string) (netlink.Link, error) {
	link, err := netHandle.LinkByName(bridgeName)
	if err != nil {
		return nil, fmt.Errorf("LinkByName() failed for bridge name %s: %s", bridgeName, err)
	}

	bridgeLink, ok := link.(*netlink.Bridge)
	if ok == false {
		return nil, fmt.Errorf("Incorrect link type %s", link.Type())
	}

	return bridgeLink, nil
}

func bridgeNetworkPair(netPair NetworkInterfacePair) error {
	netHandle, err := netlink.NewHandle()
	if err != nil {
		return err
	}
	defer netHandle.Delete()

	tapLink, err := createTAP(netHandle, netPair.TAPIface.Name)
	if err != nil {
		return fmt.Errorf("Could not create TAP interface: %s", err)
	}

	vethLink, err := getVeth(netHandle, netPair.VirtIface.Name)
	if err != nil {
		return fmt.Errorf("Could not get veth interface: %s", err)
	}

	hardAddr, err := net.ParseMAC(netPair.VirtIface.HardAddr)
	if err != nil {
		return err
	}
	if err := netHandle.LinkSetHardwareAddr(vethLink, hardAddr); err != nil {
		return fmt.Errorf("Could not set MAC address %s for veth interface %s: %s",
			netPair.VirtIface.HardAddr, netPair.VirtIface.Name, err)
	}

	bridgeLink, err := createBridge(netHandle, netPair.Name)
	if err != nil {
		return fmt.Errorf("Could not create bridge: %s", err)
	}

	if err := netHandle.LinkSetMaster(tapLink, bridgeLink.(*netlink.Bridge)); err != nil {
		return fmt.Errorf("Could not attach TAP %s to the bridge %s: %s",
			netPair.TAPIface.Name, netPair.Name, err)
	}

	if err := netHandle.LinkSetUp(tapLink); err != nil {
		return fmt.Errorf("Could not enable TAP %s: %s", netPair.TAPIface.Name, err)
	}

	if err := netHandle.LinkSetMaster(vethLink, bridgeLink.(*netlink.Bridge)); err != nil {
		return fmt.Errorf("Could not attach veth %s to the bridge %s: %s",
			netPair.VirtIface.Name, netPair.Name, err)
	}

	if err := netHandle.LinkSetUp(vethLink); err != nil {
		return fmt.Errorf("Could not enable veth %s: %s", netPair.VirtIface.Name, err)
	}

	if err := netHandle.LinkSetUp(bridgeLink); err != nil {
		return fmt.Errorf("Could not enable bridge %s: %s", netPair.Name, err)
	}

	return nil
}

func unBridgeNetworkPair(netPair NetworkInterfacePair) error {
	netHandle, err := netlink.NewHandle()
	if err != nil {
		return err
	}
	defer netHandle.Delete()

	tapLink, err := getTAP(netHandle, netPair.TAPIface.Name)
	if err != nil {
		return fmt.Errorf("Could not get TAP interface: %s", err)
	}

	vethLink, err := getVeth(netHandle, netPair.VirtIface.Name)
	if err != nil {
		return fmt.Errorf("Could not get veth interface: %s", err)
	}

	bridgeLink, err := getBridge(netHandle, netPair.Name)
	if err != nil {
		return fmt.Errorf("Could not get bridge interface: %s", err)
	}

	if err := netHandle.LinkSetDown(bridgeLink); err != nil {
		return fmt.Errorf("Could not disable bridge %s: %s", netPair.Name, err)
	}

	if err := netHandle.LinkSetDown(vethLink); err != nil {
		return fmt.Errorf("Could not disable veth %s: %s", netPair.VirtIface.Name, err)
	}

	if err := netHandle.LinkSetNoMaster(vethLink); err != nil {
		return fmt.Errorf("Could not detach veth %s: %s", netPair.VirtIface.Name, err)
	}

	if err := netHandle.LinkSetDown(tapLink); err != nil {
		return fmt.Errorf("Could not disable TAP %s: %s", netPair.TAPIface.Name, err)
	}

	if err := netHandle.LinkSetNoMaster(tapLink); err != nil {
		return fmt.Errorf("Could not detach TAP %s: %s", netPair.TAPIface.Name, err)
	}

	if err := netHandle.LinkDel(bridgeLink); err != nil {
		return fmt.Errorf("Could not remove bridge %s: %s", netPair.Name, err)
	}

	if err := netHandle.LinkDel(tapLink); err != nil {
		return fmt.Errorf("Could not remove TAP %s: %s", netPair.TAPIface.Name, err)
	}

	return nil
}

func createNetNS() (string, error) {
	n, err := ns.NewNS()
	if err != nil {
		return "", err
	}

	return n.Path(), nil
}

func setNetNS(netNSPath string) error {
	n, err := ns.GetNS(netNSPath)
	if err != nil {
		return err
	}

	return n.Set()
}

func doNetNS(netNSPath string, cb func(ns.NetNS) error) error {
	n, err := ns.GetNS(netNSPath)
	if err != nil {
		return err
	}

	return n.Do(cb)
}

func deleteNetNS(netNSPath string, mounted bool) error {
	n, err := ns.GetNS(netNSPath)
	if err != nil {
		return err
	}

	err = n.Close()
	if err != nil {
		return err
	}

	// This unmount part is supposed to be done in the cni/ns package, but the "mounted"
	// flag is not updated when retrieving NetNs handler from GetNS().
	if mounted {
		if err = unix.Unmount(netNSPath, unix.MNT_DETACH); err != nil {
			return fmt.Errorf("Failed to unmount namespace %s: %v", netNSPath, err)
		}
		if err := os.RemoveAll(netNSPath); err != nil {
			return fmt.Errorf("Failed to clean up namespace %s: %v", netNSPath, err)
		}
	}

	return nil
}

func createNetworkEndpoint(idx int, uniqueID string, ifName string) (Endpoint, error) {
	if idx < 0 {
		return Endpoint{}, fmt.Errorf("invalid network endpoint index: %d", idx)
	}
	if uniqueID == "" {
		return Endpoint{}, errors.New("uniqueID cannot be blank")
	}

	hardAddr := net.HardwareAddr{0x02, 0x00, 0xCA, 0xFE, byte(idx >> 8), byte(idx)}

	endpoint := Endpoint{
		NetPair: NetworkInterfacePair{
			ID:   fmt.Sprintf("%s-%d", uniqueID, idx),
			Name: fmt.Sprintf("br%d", idx),
			VirtIface: NetworkInterface{
				Name:     fmt.Sprintf("eth%d", idx),
				HardAddr: hardAddr.String(),
			},
			TAPIface: NetworkInterface{
				Name: fmt.Sprintf("tap%d", idx),
			},
		},
	}

	if ifName != "" {
		endpoint.NetPair.VirtIface.Name = ifName
	}

	return endpoint, nil
}

func createNetworkEndpoints(numOfEndpoints int) (endpoints []Endpoint, err error) {
	if numOfEndpoints < 1 {
		return endpoints, fmt.Errorf("Invalid number of network endpoints")
	}

	uniqueID := uuid.Generate().String()

	for i := 0; i < numOfEndpoints; i++ {
		endpoint, err := createNetworkEndpoint(i, uniqueID, "")
		if err != nil {
			return nil, err
		}
		endpoints = append(endpoints, endpoint)
	}

	return endpoints, nil
}

func getIfacesFromNetNs(networkNSPath string) ([]net.Interface, error) {
	var ifaces []net.Interface
	var err error

	if networkNSPath == "" {
		return []net.Interface{}, fmt.Errorf("Network namespace path cannot be empty")
	}

	err = doNetNS(networkNSPath, func(_ ns.NetNS) error {
		ifaces, err = net.Interfaces()
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return []net.Interface{}, err
	}

	return ifaces, nil
}

func getNetIfaceByName(name string, netIfaces []net.Interface) (net.Interface, error) {
	for _, netIface := range netIfaces {
		if netIface.Name == name {
			return netIface, nil
		}
	}

	return net.Interface{}, fmt.Errorf("Could not find the interface %s in the list", name)
}

func addNetDevHypervisor(pod Pod, endpoints []Endpoint) error {
	return pod.hypervisor.addDevice(endpoints, netDev)
}

// network is the virtcontainers network interface.
// Container network plugins are used to setup virtual network
// between VM netns and the host network physical interface.
type network interface {
	// init initializes the network, setting a new network namespace.
	init(config *NetworkConfig) error

	// run runs a callback function in a specified network namespace.
	run(networkNSPath string, cb func() error) error

	// add adds all needed interfaces inside the network namespace.
	add(pod Pod, config NetworkConfig) (NetworkNamespace, error)

	// remove unbridges and deletes TAP interfaces. It also removes virtual network
	// interfaces and deletes the network namespace.
	remove(pod Pod, networkNS NetworkNamespace) error
}
