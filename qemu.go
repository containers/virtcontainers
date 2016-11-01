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
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	ciaoQemu "github.com/01org/ciao/qemu"
	"github.com/golang/glog"
)

type qmpChannel struct {
	ctx          context.Context
	path         string
	disconnectCh chan struct{}
	commandCh    chan qmpCommand
	wg           sync.WaitGroup
	qmp          *ciaoQemu.QMP
}

// qemu is an Hypervisor interface implementation for the Linux qemu hypervisor.
type qemu struct {
	path   string
	config HypervisorConfig

	hypervisorParams []string
	kernelParams     []string

	qmpMonitorCh qmpChannel
	qmpControlCh qmpChannel

	qemuConfig ciaoQemu.Config
}

// QMPCommand describes a VirtContainers QMP command to be sent.
type qmpCommand uint8

const (
	// qmpQuit will shut the VM down.
	qmpQuit qmpCommand = iota

	// qmpStart will start/resume the VM.
	qmpStart

	// qmpStop will stop/pause the VM.
	qmpStop
)

const defaultQemuPath = "/usr/bin/qemu-system-x86_64"

const (
	defaultCPUs    = 2
	defaultCores   = 1
	defaultSockets = 2
	defaultThreads = 1
)

const (
	defaultMemSize  = "2G"
	defaultMemSlots = 2
	defaultMemMax   = "3G"
)

type qmpGlogLogger struct{}

func (l qmpGlogLogger) V(level int32) bool {
	return bool(glog.V(glog.Level(level)))
}

func (l qmpGlogLogger) Infof(format string, v ...interface{}) {
	glog.InfoDepth(2, fmt.Sprintf(format, v...))
}

func (l qmpGlogLogger) Warningf(format string, v ...interface{}) {
	glog.WarningDepth(2, fmt.Sprintf(format, v...))
}

func (l qmpGlogLogger) Errorf(format string, v ...interface{}) {
	glog.ErrorDepth(2, fmt.Sprintf(format, v...))
}

var kernelDefaultParams = []Param{
	{"root", "/dev/pmem0p1"},
	{"rootflags", "dax,data=ordered,errors=remount-ro rw"},
	{"rootfstype", "ext4"},
	{"tsc", "reliable"},
	{"no_timer_check", ""},
	{"rcupdate.rcu_expedited", "1"},
	{"i8042.direct", "1"},
	{"i8042.dumbkbd", "1"},
	{"i8042.nopnp", "1"},
	{"i8042.noaux", "1"},
	{"noreplace-smp", ""},
	{"reboot", "k"},
	{"panic", "1"},
	{"console", "hvc0"},
	{"console", "hvc1"},
	{"initcall_debug", ""},
	{"init", "/usr/lib/systemd/systemd"},
	{"systemd.unit", "container.target"},
	{"iommu", "off"},
	{"quiet", ""},
	{"systemd.mask", "systemd-networkd.service"},
	{"systemd.mask", "systemd-networkd.socket"},
	{"systemd.show_status", "false"},
	{"cryptomgr.notests", ""},
}

func (q *qemu) buildKernelParams(config HypervisorConfig) error {
	params := kernelDefaultParams
	params = append(params, config.KernelParams...)

	q.kernelParams = serializeParams(params, "=")

	return nil
}

func (q *qemu) appendVolume(devices []ciaoQemu.Device, volume Volume) []ciaoQemu.Device {
	if volume.MountTag == "" || volume.HostPath == "" {
		return devices
	}

	devices = append(devices,
		ciaoQemu.FSDevice{
			Driver:        ciaoQemu.Virtio9P,
			FSDriver:      ciaoQemu.Local,
			ID:            fmt.Sprintf("extra-%s-9p", volume.MountTag),
			Path:          volume.HostPath,
			MountTag:      volume.MountTag,
			SecurityModel: ciaoQemu.None,
		},
	)

	return devices
}

func (q *qemu) appendSocket(devices []ciaoQemu.Device, socket Socket) []ciaoQemu.Device {
	devices = append(devices,
		ciaoQemu.CharDevice{
			Driver:   ciaoQemu.VirtioSerialPort,
			Backend:  ciaoQemu.Socket,
			DeviceID: socket.DeviceID,
			ID:       socket.ID,
			Path:     socket.HostPath,
			Name:     socket.Name,
		},
	)

	return devices
}

func (q *qemu) appendSockets(devices []ciaoQemu.Device, podConfig PodConfig) []ciaoQemu.Device {
	for _, s := range podConfig.Sockets {
		devices = q.appendSocket(devices, s)
	}

	return devices
}

func (q *qemu) appendFSDevices(devices []ciaoQemu.Device, podConfig PodConfig) []ciaoQemu.Device {
	if podConfig.ID != "" {
		// Add the pod rootfs
		devices = append(devices,
			ciaoQemu.FSDevice{
				Driver:        ciaoQemu.Virtio9P,
				FSDriver:      ciaoQemu.Local,
				ID:            fmt.Sprintf("pod-%s-9p", podConfig.ID),
				Path:          podConfig.RootFs,
				MountTag:      fmt.Sprintf("pod-rootfs-%s", podConfig.ID),
				SecurityModel: ciaoQemu.None,
			},
		)
	}

	// Add the containers rootfs
	for _, c := range podConfig.Containers {
		if c.RootFs == "" || c.ID == "" {
			continue
		}

		devices = append(devices,
			ciaoQemu.FSDevice{
				Driver:   ciaoQemu.Virtio9P,
				FSDriver: ciaoQemu.Local,
				ID:       fmt.Sprintf("ctr-%s-9p", c.ID),
				Path:     c.RootFs,
				//MountTag:      fmt.Sprintf("ctr-rootfs-%s", c.ID),
				MountTag:      "rootfs", // CC hack, systemd mounts rootfs.
				SecurityModel: ciaoQemu.None,
			},
		)
	}

	// Add the shared volumes
	for _, v := range podConfig.Volumes {
		devices = q.appendVolume(devices, v)
	}

	return devices
}

func (q *qemu) appendConsoles(devices []ciaoQemu.Device, podConfig PodConfig) []ciaoQemu.Device {
	serial := ciaoQemu.SerialDevice{
		Driver: ciaoQemu.VirtioSerial,
		ID:     "serial0",
	}

	devices = append(devices, serial)

	for i, c := range podConfig.Containers {
		var console ciaoQemu.CharDevice
		if c.Interactive == false || c.Console == "" {
			consolePath := fmt.Sprintf("%s/%s/console.sock", runStoragePath, podConfig.ID)

			console = ciaoQemu.CharDevice{
				Driver:   ciaoQemu.Console,
				Backend:  ciaoQemu.Socket,
				DeviceID: fmt.Sprintf("console%d", i),
				ID:       fmt.Sprintf("charconsole%d", i),
				Path:     consolePath,
			}
		} else {
			console = ciaoQemu.CharDevice{
				Driver:   ciaoQemu.Console,
				Backend:  ciaoQemu.Serial,
				DeviceID: fmt.Sprintf("console%d", i),
				ID:       fmt.Sprintf("charconsole%d", i),
				Path:     c.Console,
			}
		}

		devices = append(devices, console)
	}

	return devices
}

func (q *qemu) appendImage(devices []ciaoQemu.Device, podConfig PodConfig) ([]ciaoQemu.Device, error) {
	imageFile, err := os.Open(q.config.ImagePath)
	if err != nil {
		return nil, err
	}
	defer imageFile.Close()

	imageStat, err := imageFile.Stat()
	if err != nil {
		return nil, err
	}

	object := ciaoQemu.Object{
		Driver:   ciaoQemu.NVDIMM,
		Type:     ciaoQemu.MemoryBackendFile,
		DeviceID: "nv0",
		ID:       "mem0",
		MemPath:  q.config.ImagePath,
		Size:     (uint64)(imageStat.Size()),
	}

	devices = append(devices, object)

	return devices, nil
}

// init intializes the Qemu structure.
func (q *qemu) init(config HypervisorConfig) error {
	valid, err := config.valid()
	if valid == false || err != nil {
		return err
	}

	p := config.HypervisorPath
	if p == "" {
		p = defaultQemuPath
	}

	q.config = config
	q.path = p

	err = q.buildKernelParams(config)
	if err != nil {
		return err
	}

	return nil
}

func (q *qemu) qmpMonitor(connectedCh chan struct{}) {
	defer func(qemu *qemu) {
		if q.qmpMonitorCh.qmp != nil {
			q.qmpMonitorCh.qmp.Shutdown()
		}

		q.qmpMonitorCh.wg.Done()
	}(q)

	cfg := ciaoQemu.QMPConfig{Logger: qmpGlogLogger{}}
	qmp, ver, err := ciaoQemu.QMPStart(q.qmpMonitorCh.ctx, q.qmpMonitorCh.path, cfg, q.qmpMonitorCh.disconnectCh)
	if err != nil {
		glog.Errorf("Failed to connect to QEMU instance %v", err)
		return
	}

	q.qmpMonitorCh.qmp = qmp

	glog.Infof("QMP version %d.%d.%d", ver.Major, ver.Minor, ver.Micro)
	glog.Infof("QMP capabilities %s", ver.Capabilities)

	err = q.qmpMonitorCh.qmp.ExecuteQMPCapabilities(q.qmpMonitorCh.ctx)
	if err != nil {
		glog.Errorf("Unable to send qmp_capabilities command: %v", err)
		return
	}

	close(connectedCh)

DONE:
	for {
		cmd, ok := <-q.qmpMonitorCh.commandCh
		if !ok {
			break DONE
		}
		switch cmd {
		case qmpStart:
			err = q.qmpMonitorCh.qmp.ExecuteCont(q.qmpMonitorCh.ctx)
			if err != nil {
				glog.Warningf("Failed to execute start command: %v", err)
			}

		case qmpStop:
			err = q.qmpMonitorCh.qmp.ExecuteStop(q.qmpMonitorCh.ctx)
			if err != nil {
				glog.Warningf("Failed to execute stop command: %v", err)
			}

		case qmpQuit:
			err = q.qmpMonitorCh.qmp.ExecuteQuit(q.qmpMonitorCh.ctx)
			if err != nil {
				glog.Warningf("Failed to execute quit command: %v", err)
			}
		}
	}
}

func (q *qemu) qmpStop() error {
	if q.qmpMonitorCh.commandCh == nil {
		return fmt.Errorf("Invalid QMP monitor channel")
	}

	q.qmpMonitorCh.commandCh <- qmpStop

	return nil
}

func (q *qemu) qmpStart() error {
	if q.qmpMonitorCh.commandCh == nil {
		return fmt.Errorf("Invalid QMP monitor channel")
	}

	q.qmpMonitorCh.commandCh <- qmpStart

	return nil
}

func (q *qemu) setCPUResources(podConfig PodConfig) (ciaoQemu.SMP, error) {
	var err error

	cpus := defaultCPUs
	if podConfig.VMConfig.CPUs != "" {
		cpus, err = strconv.Atoi(podConfig.VMConfig.CPUs)
		if err != nil {
			return ciaoQemu.SMP{}, err
		}
	}

	cores := defaultCores
	if podConfig.VMConfig.Cores != "" {
		cores, err = strconv.Atoi(podConfig.VMConfig.Cores)
		if err != nil {
			return ciaoQemu.SMP{}, err
		}
	}

	sockets := defaultSockets
	if podConfig.VMConfig.Sockets != "" {
		sockets, err = strconv.Atoi(podConfig.VMConfig.Sockets)
		if err != nil {
			return ciaoQemu.SMP{}, err
		}
	}

	threads := defaultThreads
	if podConfig.VMConfig.Threads != "" {
		threads, err = strconv.Atoi(podConfig.VMConfig.Threads)
		if err != nil {
			return ciaoQemu.SMP{}, err
		}
	}

	smp := ciaoQemu.SMP{
		CPUs:    uint32(cpus),
		Cores:   uint32(cores),
		Sockets: uint32(sockets),
		Threads: uint32(threads),
	}

	return smp, nil
}

func (q *qemu) setMemoryResources(podConfig PodConfig) (ciaoQemu.Memory, error) {
	var err error

	size := defaultMemSize
	if podConfig.VMConfig.MemSize != "" {
		size = podConfig.VMConfig.MemSize
	}

	slots := defaultMemSlots
	if podConfig.VMConfig.MemSlots != "" {
		slots, err = strconv.Atoi(podConfig.VMConfig.MemSlots)
		if err != nil {
			return ciaoQemu.Memory{}, err
		}
	}

	maxMem := defaultMemMax
	if podConfig.VMConfig.MemMax != "" {
		maxMem = podConfig.VMConfig.MemMax
	}

	memory := ciaoQemu.Memory{
		Size:   size,
		Slots:  uint8(slots),
		MaxMem: maxMem,
	}

	return memory, nil
}

// createPod is the Hypervisor pod creation implementation for ciaoQemu.
func (q *qemu) createPod(podConfig PodConfig) error {
	var devices []ciaoQemu.Device

	machine := ciaoQemu.Machine{
		Type:         "pc-lite",
		Acceleration: "kvm,kernel_irqchip,nvdimm",
	}

	smp, err := q.setCPUResources(podConfig)
	if err != nil {
		return nil
	}

	memory, err := q.setMemoryResources(podConfig)
	if err != nil {
		return nil
	}

	knobs := ciaoQemu.Knobs{
		NoUserConfig: true,
		NoDefaults:   true,
		NoGraphic:    true,
		Daemonize:    true,
	}

	kernel := ciaoQemu.Kernel{
		Path:   q.config.KernelPath,
		Params: strings.Join(q.kernelParams, " "),
	}

	rtc := ciaoQemu.RTC{
		Base:     "utc",
		DriftFix: "slew",
	}

	q.qmpMonitorCh = qmpChannel{
		ctx:  context.Background(),
		path: fmt.Sprintf("%s/%s/%s", runStoragePath, podConfig.ID, monitorSocket),
	}

	q.qmpControlCh = qmpChannel{
		ctx:  context.Background(),
		path: fmt.Sprintf("%s/%s/%s", runStoragePath, podConfig.ID, controlSocket),
	}

	qmpSockets := []ciaoQemu.QMPSocket{
		{
			Type:   "unix",
			Name:   q.qmpMonitorCh.path,
			Server: true,
			NoWait: true,
		},
		{
			Type:   "unix",
			Name:   q.qmpControlCh.path,
			Server: true,
			NoWait: true,
		},
	}

	devices = q.appendFSDevices(devices, podConfig)
	devices = q.appendConsoles(devices, podConfig)
	devices = q.appendSockets(devices, podConfig)
	devices, err = q.appendImage(devices, podConfig)
	if err != nil {
		return err
	}

	qemuConfig := ciaoQemu.Config{
		Name:        fmt.Sprintf("pod-%s", podConfig.ID),
		UUID:        podConfig.ID,
		Path:        q.path,
		Ctx:         q.qmpMonitorCh.ctx,
		Machine:     machine,
		SMP:         smp,
		Memory:      memory,
		Devices:     devices,
		CPUModel:    "host",
		Kernel:      kernel,
		RTC:         rtc,
		QMPSockets:  qmpSockets,
		Knobs:       knobs,
		VGA:         "none",
		GlobalParam: "kvm-pit.lost_tick_policy=discard",
	}

	q.qemuConfig = qemuConfig

	return nil
}

// startPod will start the Pod's VM.
func (q *qemu) startPod(startCh, stopCh chan struct{}) error {
	strErr, err := ciaoQemu.LaunchQemu(q.qemuConfig, qmpGlogLogger{})
	if err != nil {
		return fmt.Errorf("%s", strErr)
	}

	// Start the QMP monitoring thread
	q.qmpMonitorCh.commandCh = make(chan qmpCommand)
	q.qmpMonitorCh.disconnectCh = stopCh
	q.qmpMonitorCh.wg.Add(1)
	q.qmpMonitor(startCh)

	return nil
}

// stopPod will stop the Pod's VM.
func (q *qemu) stopPod() error {
	cfg := ciaoQemu.QMPConfig{Logger: qmpGlogLogger{}}
	q.qmpControlCh.disconnectCh = make(chan struct{})

	qmp, _, err := ciaoQemu.QMPStart(q.qmpControlCh.ctx, q.qmpControlCh.path, cfg, q.qmpControlCh.disconnectCh)
	if err != nil {
		glog.Errorf("Failed to connect to QEMU instance %v", err)
		return err
	}

	err = qmp.ExecuteQMPCapabilities(q.qmpMonitorCh.ctx)
	if err != nil {
		glog.Errorf("Failed to negotiate capabilities with QEMU %v", err)
		return err
	}

	return qmp.ExecuteQuit(q.qmpMonitorCh.ctx)
}

// addDevice will add extra devices to Qemu command line.
func (q *qemu) addDevice(devInfo interface{}, devType deviceType) error {
	switch devType {
	case fsDev:
		volume := devInfo.(Volume)
		q.qemuConfig.Devices = q.appendVolume(q.qemuConfig.Devices, volume)
	case serialPortDev:
		socket := devInfo.(Socket)
		q.qemuConfig.Devices = q.appendSocket(q.qemuConfig.Devices, socket)
	default:
		break
	}

	return nil
}
