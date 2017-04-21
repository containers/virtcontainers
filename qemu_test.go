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
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	ciaoQemu "github.com/01org/ciao/qemu"
)

func newQemuConfig() HypervisorConfig {
	return HypervisorConfig{
		KernelPath:     testQemuKernelPath,
		ImagePath:      testQemuImagePath,
		HypervisorPath: testQemuPath,
	}
}

func testQemuBuildKernelParams(t *testing.T, kernelParams []Param, expected string, debug bool) {
	qemuConfig := newQemuConfig()
	qemuConfig.KernelParams = kernelParams

	if debug == true {
		qemuConfig.Debug = true
	}

	q := &qemu{}

	err := q.buildKernelParams(qemuConfig)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Join(q.kernelParams, " ") != expected {
		t.Fatal()
	}
}

var testQemuKernelParamsBase = "root=/dev/pmem0p1 rootflags=dax,data=ordered,errors=remount-ro rw rootfstype=ext4 tsc=reliable no_timer_check rcupdate.rcu_expedited=1 i8042.direct=1 i8042.dumbkbd=1 i8042.nopnp=1 i8042.noaux=1 noreplace-smp reboot=k panic=1 console=hvc0 console=hvc1 initcall_debug init=/usr/lib/systemd/systemd systemd.unit=cc-agent.target iommu=off systemd.mask=systemd-networkd.service systemd.mask=systemd-networkd.socket cryptomgr.notests"
var testQemuKernelParamsNonDebug = "quiet systemd.show_status=false"
var testQemuKernelParamsDebug = "debug systemd.show_status=true systemd.log_level=debug"

func TestQemuBuildKernelParamsFoo(t *testing.T) {
	// two representations of the same kernel parameters
	suffixStr := "foo=foo bar=bar"
	suffixParams := []Param{
		{
			parameter: "foo",
			value:     "foo",
		},
		{
			parameter: "bar",
			value:     "bar",
		},
	}

	type testData struct {
		debugParams string
		debugValue  bool
	}

	data := []testData{
		{testQemuKernelParamsNonDebug, false},
		{testQemuKernelParamsDebug, true},
	}

	for _, d := range data {
		// kernel params consist of a default set of params,
		// followed by a set of params that depend on whether
		// debug mode is enabled and end with any user-supplied
		// params.
		expected := []string{testQemuKernelParamsBase, d.debugParams, suffixStr}

		expectedOut := strings.Join(expected, " ")

		testQemuBuildKernelParams(t, suffixParams, expectedOut, d.debugValue)
	}
}

func testQemuAppend(t *testing.T, structure interface{}, expected []ciaoQemu.Device, devType deviceType) {
	var devices []ciaoQemu.Device
	q := &qemu{}

	switch s := structure.(type) {
	case Volume:
		devices = q.appendVolume(devices, s)
	case Socket:
		devices = q.appendSocket(devices, s)
	case PodConfig:
		switch devType {
		case fsDev:
			devices = q.appendFSDevices(devices, s)
		case consoleDev:
			devices = q.appendConsoles(devices, s)
		}
	}

	if reflect.DeepEqual(devices, expected) == false {
		t.Fatalf("Got %v\nExpecting %v", devices, expected)
	}
}

func TestQemuAppendVolume(t *testing.T) {
	mountTag := "testMountTag"
	hostPath := "testHostPath"

	expectedOut := []ciaoQemu.Device{
		ciaoQemu.FSDevice{
			Driver:        ciaoQemu.Virtio9P,
			FSDriver:      ciaoQemu.Local,
			ID:            fmt.Sprintf("extra-9p-%s", mountTag),
			Path:          hostPath,
			MountTag:      mountTag,
			SecurityModel: ciaoQemu.None,
		},
	}

	volume := Volume{
		MountTag: mountTag,
		HostPath: hostPath,
	}

	testQemuAppend(t, volume, expectedOut, -1)
}

func TestQemuAppendSocket(t *testing.T) {
	deviceID := "channelTest"
	id := "charchTest"
	hostPath := "/tmp/hyper_test.sock"
	name := "sh.hyper.channel.test"

	expectedOut := []ciaoQemu.Device{
		ciaoQemu.CharDevice{
			Driver:   ciaoQemu.VirtioSerialPort,
			Backend:  ciaoQemu.Socket,
			DeviceID: deviceID,
			ID:       id,
			Path:     hostPath,
			Name:     name,
		},
	}

	socket := Socket{
		DeviceID: deviceID,
		ID:       id,
		HostPath: hostPath,
		Name:     name,
	}

	testQemuAppend(t, socket, expectedOut, -1)
}

func TestQemuAppendFSDevices(t *testing.T) {
	podID := "testPodID"
	contID := "testContID"
	contRootFs := "testContRootFs"
	volMountTag := "testVolMountTag"
	volHostPath := "testVolHostPath"

	expectedOut := []ciaoQemu.Device{
		ciaoQemu.FSDevice{
			Driver:        ciaoQemu.Virtio9P,
			FSDriver:      ciaoQemu.Local,
			ID:            "ctr-9p-0",
			Path:          fmt.Sprintf("%s.1", contRootFs),
			MountTag:      "ctr-rootfs-0",
			SecurityModel: ciaoQemu.None,
		},
		ciaoQemu.FSDevice{
			Driver:        ciaoQemu.Virtio9P,
			FSDriver:      ciaoQemu.Local,
			ID:            "ctr-9p-1",
			Path:          fmt.Sprintf("%s.2", contRootFs),
			MountTag:      "ctr-rootfs-1",
			SecurityModel: ciaoQemu.None,
		},
		ciaoQemu.FSDevice{
			Driver:        ciaoQemu.Virtio9P,
			FSDriver:      ciaoQemu.Local,
			ID:            fmt.Sprintf("extra-9p-%s", fmt.Sprintf("%s.1", volMountTag)),
			Path:          fmt.Sprintf("%s.1", volHostPath),
			MountTag:      fmt.Sprintf("%s.1", volMountTag),
			SecurityModel: ciaoQemu.None,
		},
		ciaoQemu.FSDevice{
			Driver:        ciaoQemu.Virtio9P,
			FSDriver:      ciaoQemu.Local,
			ID:            fmt.Sprintf("extra-9p-%s", fmt.Sprintf("%s.2", volMountTag)),
			Path:          fmt.Sprintf("%s.2", volHostPath),
			MountTag:      fmt.Sprintf("%s.2", volMountTag),
			SecurityModel: ciaoQemu.None,
		},
	}

	volumes := []Volume{
		{
			MountTag: fmt.Sprintf("%s.1", volMountTag),
			HostPath: fmt.Sprintf("%s.1", volHostPath),
		},
		{
			MountTag: fmt.Sprintf("%s.2", volMountTag),
			HostPath: fmt.Sprintf("%s.2", volHostPath),
		},
	}

	containers := []ContainerConfig{
		{
			ID:     fmt.Sprintf("%s.1", contID),
			RootFs: fmt.Sprintf("%s.1", contRootFs),
		},
		{
			ID:     fmt.Sprintf("%s.2", contID),
			RootFs: fmt.Sprintf("%s.2", contRootFs),
		},
	}

	podConfig := PodConfig{
		ID:         podID,
		Volumes:    volumes,
		Containers: containers,
	}

	testQemuAppend(t, podConfig, expectedOut, fsDev)
}

func TestQemuAppendConsoles(t *testing.T) {
	podID := "testPodID"

	expectedOut := []ciaoQemu.Device{
		ciaoQemu.SerialDevice{
			Driver: ciaoQemu.VirtioSerial,
			ID:     "serial0",
		},
		ciaoQemu.CharDevice{
			Driver:   ciaoQemu.Console,
			Backend:  ciaoQemu.Socket,
			DeviceID: "console0",
			ID:       "charconsole0",
			Path:     filepath.Join(runStoragePath, podID, defaultConsole),
		},
	}

	podConfig := PodConfig{
		ID:         podID,
		Containers: []ContainerConfig{},
	}

	testQemuAppend(t, podConfig, expectedOut, consoleDev)
}

func TestQemuAppendImage(t *testing.T) {
	var devices []ciaoQemu.Device

	qemuConfig := newQemuConfig()
	q := &qemu{
		config: qemuConfig,
	}

	imageFile, err := os.Open(q.config.ImagePath)
	if err != nil {
		t.Fatal(err)
	}
	defer imageFile.Close()

	imageStat, err := imageFile.Stat()
	if err != nil {
		t.Fatal(err)
	}

	expectedOut := []ciaoQemu.Device{
		ciaoQemu.Object{
			Driver:   ciaoQemu.NVDIMM,
			Type:     ciaoQemu.MemoryBackendFile,
			DeviceID: "nv0",
			ID:       "mem0",
			MemPath:  q.config.ImagePath,
			Size:     (uint64)(imageStat.Size()),
		},
	}

	podConfig := PodConfig{}

	devices, err = q.appendImage(devices, podConfig)
	if err != nil {
		t.Fatal(err)
	}

	if reflect.DeepEqual(devices, expectedOut) == false {
		t.Fatalf("Got %v\nExpecting %v", devices, expectedOut)
	}
}

func TestQemuInit(t *testing.T) {
	qemuConfig := newQemuConfig()
	q := &qemu{}

	err := q.init(qemuConfig)
	if err != nil {
		t.Fatal(err)
	}

	if reflect.DeepEqual(qemuConfig, q.config) == false {
		t.Fatalf("Got %v\nExpecting %v", q.config, qemuConfig)
	}

	if reflect.DeepEqual(qemuConfig.HypervisorPath, q.path) == false {
		t.Fatalf("Got %v\nExpecting %v", q.path, qemuConfig.HypervisorPath)
	}

	// non-debug is the default
	var testQemuKernelParamsDefault = testQemuKernelParamsBase + " " + testQemuKernelParamsNonDebug

	if strings.Join(q.kernelParams, " ") != testQemuKernelParamsDefault {
		t.Fatal()
	}
}

func TestQemuSetCPUResources(t *testing.T) {
	vcpus := 1

	q := &qemu{}

	expectedOut := ciaoQemu.SMP{
		CPUs:    uint32(vcpus),
		Cores:   uint32(vcpus),
		Sockets: uint32(1),
		Threads: uint32(1),
	}

	vmConfig := Resources{
		VCPUs: uint(vcpus),
	}

	podConfig := PodConfig{
		VMConfig: vmConfig,
	}

	smp := q.setCPUResources(podConfig)

	if reflect.DeepEqual(smp, expectedOut) == false {
		t.Fatalf("Got %v\nExpecting %v", smp, expectedOut)
	}
}

func TestQemuSetMemoryResources(t *testing.T) {
	mem := 1000

	q := &qemu{}

	expectedOut := ciaoQemu.Memory{
		Size:   "1000M",
		Slots:  uint8(2),
		MaxMem: "1500M",
	}

	vmConfig := Resources{
		Memory: uint(mem),
	}

	podConfig := PodConfig{
		VMConfig: vmConfig,
	}

	memory := q.setMemoryResources(podConfig)

	if reflect.DeepEqual(memory, expectedOut) == false {
		t.Fatalf("Got %v\nExpecting %v", memory, expectedOut)
	}
}

func testQemuAddDevice(t *testing.T, devInfo interface{}, devType deviceType, expected []ciaoQemu.Device) {
	q := &qemu{}

	err := q.addDevice(devInfo, devType)
	if err != nil {
		t.Fatal(err)
	}

	if reflect.DeepEqual(q.qemuConfig.Devices, expected) == false {
		t.Fatalf("Got %v\nExpecting %v", q.qemuConfig.Devices, expected)
	}
}

func TestQemuAddDeviceFsDev(t *testing.T) {
	mountTag := "testMountTag"
	hostPath := "testHostPath"

	expectedOut := []ciaoQemu.Device{
		ciaoQemu.FSDevice{
			Driver:        ciaoQemu.Virtio9P,
			FSDriver:      ciaoQemu.Local,
			ID:            fmt.Sprintf("extra-9p-%s", mountTag),
			Path:          hostPath,
			MountTag:      mountTag,
			SecurityModel: ciaoQemu.None,
		},
	}

	volume := Volume{
		MountTag: mountTag,
		HostPath: hostPath,
	}

	testQemuAddDevice(t, volume, fsDev, expectedOut)
}

func TestQemuAddDeviceSerialPordDev(t *testing.T) {
	deviceID := "channelTest"
	id := "charchTest"
	hostPath := "/tmp/hyper_test.sock"
	name := "sh.hyper.channel.test"

	expectedOut := []ciaoQemu.Device{
		ciaoQemu.CharDevice{
			Driver:   ciaoQemu.VirtioSerialPort,
			Backend:  ciaoQemu.Socket,
			DeviceID: deviceID,
			ID:       id,
			Path:     hostPath,
			Name:     name,
		},
	}

	socket := Socket{
		DeviceID: deviceID,
		ID:       id,
		HostPath: hostPath,
		Name:     name,
	}

	testQemuAddDevice(t, socket, serialPortDev, expectedOut)
}

func TestQemuGetPodConsole(t *testing.T) {
	q := &qemu{}
	podID := "testPodID"
	expected := filepath.Join(runStoragePath, podID, defaultConsole)

	if result := q.getPodConsole(podID); result != expected {
		t.Fatalf("Got %s\nExpecting %s", result, expected)
	}
}
