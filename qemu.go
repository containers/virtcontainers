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
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	cliQemu "github.com/containers/virtcontainers/pkg/qemu"
	"github.com/containers/virtcontainers/pkg/uuid"
	"github.com/sirupsen/logrus"
)

type qmpChannel struct {
	ctx          context.Context
	path         string
	disconnectCh chan struct{}
	wg           sync.WaitGroup
	qmp          *cliQemu.QMP
}

// qemu is an Hypervisor interface implementation for the Linux qemu hypervisor.
type qemu struct {
	path   string
	config HypervisorConfig

	hypervisorParams []string
	kernelParams     []string

	qmpMonitorCh qmpChannel
	qmpControlCh qmpChannel

	qemuConfig cliQemu.Config

	nestedRun bool
}

const defaultQemuPath = "/usr/bin/qemu-system-x86_64"

const defaultQemuMachineType = "pc-lite"

const defaultQemuMachineAccelerators = "kvm,kernel_irqchip,nvdimm"

const (
	// QemuPCLite is the QEMU pc-lite machine type
	QemuPCLite = defaultQemuMachineType

	// QemuPC is the QEMU pc machine type
	QemuPC = "pc"

	// QemuQ35 is the QEMU Q35 machine type
	QemuQ35 = "q35"
)

const qmpCapErrMsg = "Failed to negoatiate QMP capabilities"

// Mapping between machine types and QEMU binary paths.
var qemuPaths = map[string]string{
	QemuPCLite: "/usr/bin/qemu-lite-system-x86_64",
	QemuPC:     defaultQemuPath,
	QemuQ35:    "/usr/bin/qemu-35-system-x86_64",
}

var supportedQemuMachines = []cliQemu.Machine{
	{
		Type:         QemuPCLite,
		Acceleration: defaultQemuMachineAccelerators,
	},
	{
		Type:         QemuPC,
		Acceleration: defaultQemuMachineAccelerators,
	},
	{
		Type:         QemuQ35,
		Acceleration: defaultQemuMachineAccelerators,
	},
}

const (
	defaultSockets uint32 = 1
	defaultThreads uint32 = 1
)

const (
	defaultMemSlots uint8 = 2
)

const (
	defaultConsole = "console.sock"
)

const (
	maxDevIDSize = 31
)

const (
	// NVDIMM device needs memory space 1024MB
	// See https://github.com/clearcontainers/runtime/issues/380
	maxMemoryOffset = 1024
)

type operation int

const (
	addDevice operation = iota
	removeDevice
)

type qmpLogger struct {
	logger *logrus.Entry
}

func newQMPLogger() qmpLogger {
	return qmpLogger{
		logger: virtLog.WithField("subsystem", "qmp"),
	}
}

func (l qmpLogger) V(level int32) bool {
	if level != 0 {
		return true
	}

	return false
}

func (l qmpLogger) Infof(format string, v ...interface{}) {
	l.logger.Infof(format, v...)
}

func (l qmpLogger) Warningf(format string, v ...interface{}) {
	l.logger.Warnf(format, v...)
}

func (l qmpLogger) Errorf(format string, v ...interface{}) {
	l.logger.Errorf(format, v...)
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
	{"iommu", "off"},
	{"cryptomgr.notests", ""},
	{"net.ifnames", "0"},
}

// kernelDefaultParamsNonDebug is a list of the default kernel
// parameters that will be used in standard (non-debug) mode.
var kernelDefaultParamsNonDebug = []Param{
	{"quiet", ""},
	{"systemd.show_status", "false"},
}

// kernelDefaultParamsDebug is a list of the default kernel
// parameters that will be used in debug mode (as much boot output as
// possible).
var kernelDefaultParamsDebug = []Param{
	{"debug", ""},
	{"systemd.show_status", "true"},
	{"systemd.log_level", "debug"},
}

// Logger returns a logrus logger appropriate for logging qemu messages
func (q *qemu) Logger() *logrus.Entry {
	return virtLog.WithField("subsystem", "qemu")
}

func (q *qemu) buildKernelParams(config HypervisorConfig) error {
	params := kernelDefaultParams

	if config.Debug == true {
		params = append(params, kernelDefaultParamsDebug...)
	} else {
		params = append(params, kernelDefaultParamsNonDebug...)
	}

	params = append(params, config.KernelParams...)

	q.kernelParams = SerializeParams(params, "=")

	return nil
}

// Adds all capabilities supported by qemu implementation of hypervisor interface
func (q *qemu) capabilities() capabilities {
	var caps capabilities

	// Only pc machine type supports hotplugging drives
	if q.qemuConfig.Machine.Type == QemuPC {
		caps.setBlockDeviceHotplugSupport()
	}

	return caps
}

func (q *qemu) appendVolume(devices []cliQemu.Device, volume Volume) []cliQemu.Device {
	if volume.MountTag == "" || volume.HostPath == "" {
		return devices
	}

	devID := fmt.Sprintf("extra-9p-%s", volume.MountTag)
	if len(devID) > maxDevIDSize {
		devID = string(devID[:maxDevIDSize])
	}

	devices = append(devices,
		cliQemu.FSDevice{
			Driver:        cliQemu.Virtio9P,
			FSDriver:      cliQemu.Local,
			ID:            devID,
			Path:          volume.HostPath,
			MountTag:      volume.MountTag,
			SecurityModel: cliQemu.None,
			DisableModern: q.nestedRun,
		},
	)

	return devices
}

func (q *qemu) appendBlockDevice(devices []cliQemu.Device, drive Drive) []cliQemu.Device {
	if drive.File == "" || drive.ID == "" || drive.Format == "" {
		return devices
	}

	if len(drive.ID) > maxDevIDSize {
		drive.ID = string(drive.ID[:maxDevIDSize])
	}

	devices = append(devices,
		cliQemu.BlockDevice{
			Driver:        cliQemu.VirtioBlock,
			ID:            drive.ID,
			File:          drive.File,
			AIO:           cliQemu.Threads,
			Format:        cliQemu.BlockDeviceFormat(drive.Format),
			Interface:     "none",
			DisableModern: q.nestedRun,
		},
	)

	return devices
}

func (q *qemu) appendVFIODevice(devices []cliQemu.Device, vfDevice VFIODevice) []cliQemu.Device {
	if vfDevice.BDF == "" {
		return devices
	}

	devices = append(devices,
		cliQemu.VFIODevice{
			BDF: vfDevice.BDF,
		},
	)

	return devices
}

func (q *qemu) appendSocket(devices []cliQemu.Device, socket Socket) []cliQemu.Device {
	devID := socket.ID
	if len(devID) > maxDevIDSize {
		devID = string(devID[:maxDevIDSize])
	}

	devices = append(devices,
		cliQemu.CharDevice{
			Driver:   cliQemu.VirtioSerialPort,
			Backend:  cliQemu.Socket,
			DeviceID: socket.DeviceID,
			ID:       devID,
			Path:     socket.HostPath,
			Name:     socket.Name,
		},
	)

	return devices
}

func networkModelToQemuType(model NetInterworkingModel) cliQemu.NetDeviceType {
	switch model {
	case ModelBridged:
		return cliQemu.TAP
	case ModelMacVtap:
		return cliQemu.MACVTAP
	//case ModelEnlightened:
	// Here the Network plugin will create a VM native interface
	// which could be MacVtap, IpVtap, SRIOV, veth-tap, vhost-user
	// In these cases we will determine the interface type here
	// and pass in the native interface through
	default:
		//TAP should work for most other cases
		return cliQemu.TAP
	}
}

func (q *qemu) appendNetworks(devices []cliQemu.Device, endpoints []Endpoint) []cliQemu.Device {
	for idx, endpoint := range endpoints {
		devices = append(devices,
			cliQemu.NetDevice{
				Type:          networkModelToQemuType(endpoint.NetPair.NetInterworkingModel),
				Driver:        cliQemu.VirtioNetPCI,
				ID:            fmt.Sprintf("network-%d", idx),
				IFName:        endpoint.NetPair.TAPIface.Name,
				MACAddress:    endpoint.NetPair.TAPIface.HardAddr,
				DownScript:    "no",
				Script:        "no",
				VHost:         true,
				DisableModern: q.nestedRun,
				FDs:           endpoint.NetPair.VMFds,
			},
		)
	}

	return devices
}

func (q *qemu) appendFSDevices(devices []cliQemu.Device, podConfig PodConfig) []cliQemu.Device {
	// Add the containers rootfs
	for idx, c := range podConfig.Containers {
		if c.RootFs == "" || c.ID == "" {
			continue
		}

		devices = append(devices,
			cliQemu.FSDevice{
				Driver:        cliQemu.Virtio9P,
				FSDriver:      cliQemu.Local,
				ID:            fmt.Sprintf("ctr-9p-%d", idx),
				Path:          c.RootFs,
				MountTag:      fmt.Sprintf("ctr-rootfs-%d", idx),
				SecurityModel: cliQemu.None,
				DisableModern: q.nestedRun,
			},
		)
	}

	// Add the shared volumes
	for _, v := range podConfig.Volumes {
		devices = q.appendVolume(devices, v)
	}

	return devices
}

func (q *qemu) appendConsoles(devices []cliQemu.Device, podConfig PodConfig) []cliQemu.Device {
	serial := cliQemu.SerialDevice{
		Driver:        cliQemu.VirtioSerial,
		ID:            "serial0",
		DisableModern: q.nestedRun,
	}

	devices = append(devices, serial)

	var console cliQemu.CharDevice

	console = cliQemu.CharDevice{
		Driver:   cliQemu.Console,
		Backend:  cliQemu.Socket,
		DeviceID: "console0",
		ID:       "charconsole0",
		Path:     q.getPodConsole(podConfig.ID),
	}

	devices = append(devices, console)

	return devices
}

func (q *qemu) appendImage(devices []cliQemu.Device, podConfig PodConfig) ([]cliQemu.Device, error) {
	imageFile, err := os.Open(q.config.ImagePath)
	if err != nil {
		return nil, err
	}
	defer imageFile.Close()

	imageStat, err := imageFile.Stat()
	if err != nil {
		return nil, err
	}

	object := cliQemu.Object{
		Driver:   cliQemu.NVDIMM,
		Type:     cliQemu.MemoryBackendFile,
		DeviceID: "nv0",
		ID:       "mem0",
		MemPath:  q.config.ImagePath,
		Size:     (uint64)(imageStat.Size()),
	}

	devices = append(devices, object)

	return devices, nil
}

func (q *qemu) forceUUIDFormat(str string) string {
	re := regexp.MustCompile(`[^[0-9,a-f,A-F]]*`)
	hexStr := re.ReplaceAllLiteralString(str, ``)

	slice := []byte(hexStr)
	sliceLen := len(slice)

	var uuidSlice uuid.UUID
	uuidLen := len(uuidSlice)

	if sliceLen > uuidLen {
		copy(uuidSlice[:], slice[:uuidLen])
	} else {
		copy(uuidSlice[:], slice)
	}

	return uuidSlice.String()
}

func (q *qemu) getMachine(name string) (cliQemu.Machine, error) {
	for _, m := range supportedQemuMachines {
		if m.Type == name {
			return m, nil
		}
	}

	return cliQemu.Machine{}, fmt.Errorf("unrecognised machine type: %v", name)
}

// Build the QEMU binary path
func (q *qemu) buildPath() error {
	p := q.config.HypervisorPath
	if p != "" {
		q.path = p
		return nil
	}

	// We do not have a configured path, let's try to map one from the machine type
	machineType := q.config.HypervisorMachineType
	if machineType == "" {
		machineType = defaultQemuMachineType
	}

	p, ok := qemuPaths[machineType]
	if !ok {
		q.Logger().WithField("machine-type", machineType).Warn("Unknown machine type")
		p = defaultQemuPath
	}

	if _, err := os.Stat(p); os.IsNotExist(err) {
		return fmt.Errorf("QEMU path (%s) does not exist", p)
	}

	q.path = p

	return nil
}

// init intializes the Qemu structure.
func (q *qemu) init(config HypervisorConfig) error {
	valid, err := config.valid()
	if valid == false || err != nil {
		return err
	}

	q.config = config

	if err = q.buildPath(); err != nil {
		return err
	}

	if err = q.buildKernelParams(config); err != nil {
		return err
	}

	nested, err := RunningOnVMM(procCPUInfo)
	if err != nil {
		return err
	}

	q.Logger().WithField("inside-vm", fmt.Sprintf("%t", nested)).Debug("Checking nesting environment")

	if config.DisableNestingChecks {
		//Intentionally ignore the nesting check
		q.nestedRun = false
	} else {
		q.nestedRun = nested
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

	cfg := cliQemu.QMPConfig{Logger: newQMPLogger()}
	qmp, ver, err := cliQemu.QMPStart(q.qmpMonitorCh.ctx, q.qmpMonitorCh.path, cfg, q.qmpMonitorCh.disconnectCh)
	if err != nil {
		q.Logger().WithError(err).Error("Failed to connect to QEMU instance")
		return
	}

	q.qmpMonitorCh.qmp = qmp

	q.Logger().WithFields(logrus.Fields{
		"qmp-major-version": ver.Major,
		"qmp-minor-version": ver.Minor,
		"qmp-micro-version": ver.Micro,
		"qmp-capabilities":  strings.Join(ver.Capabilities, ","),
	}).Infof("QMP details")

	err = q.qmpMonitorCh.qmp.ExecuteQMPCapabilities(q.qmpMonitorCh.ctx)
	if err != nil {
		q.Logger().WithError(err).Error(qmpCapErrMsg)
		return
	}

	close(connectedCh)
}

func (q *qemu) setCPUResources(podConfig PodConfig) cliQemu.SMP {
	vcpus := q.config.DefaultVCPUs
	if podConfig.VMConfig.VCPUs > 0 {
		vcpus = uint32(podConfig.VMConfig.VCPUs)
	}

	smp := cliQemu.SMP{
		CPUs:    vcpus,
		Cores:   vcpus,
		Sockets: defaultSockets,
		Threads: defaultThreads,
	}

	return smp
}

func (q *qemu) setMemoryResources(podConfig PodConfig) (cliQemu.Memory, error) {
	hostMemKb, err := getHostMemorySizeKb(procMemInfo)
	if err != nil {
		return cliQemu.Memory{}, fmt.Errorf("Unable to read memory info: %s", err)
	}
	if hostMemKb == 0 {
		return cliQemu.Memory{}, fmt.Errorf("Error host memory size 0")
	}

	// add 1G memory space for nvdimm device (vm guest image)
	memMax := fmt.Sprintf("%dM", int(float64(hostMemKb)/1024)+maxMemoryOffset)
	mem := fmt.Sprintf("%dM", q.config.DefaultMemSz)
	if podConfig.VMConfig.Memory > 0 {
		mem = fmt.Sprintf("%dM", podConfig.VMConfig.Memory)
	}

	memory := cliQemu.Memory{
		Size:   mem,
		Slots:  defaultMemSlots,
		MaxMem: memMax,
	}

	return memory, nil
}

// createPod is the Hypervisor pod creation implementation for cliQemu.
func (q *qemu) createPod(podConfig PodConfig) error {
	var devices []cliQemu.Device

	machineType := q.config.HypervisorMachineType
	if machineType == "" {
		machineType = defaultQemuMachineType
	}

	machine, err := q.getMachine(machineType)
	if err != nil {
		return err
	}

	accelerators := podConfig.HypervisorConfig.MachineAccelerators
	if accelerators != "" {
		if !strings.HasPrefix(accelerators, ",") {
			accelerators = fmt.Sprintf(",%s", accelerators)
		}
		machine.Acceleration += accelerators
	}

	smp := q.setCPUResources(podConfig)

	memory, err := q.setMemoryResources(podConfig)
	if err != nil {
		return err
	}

	knobs := cliQemu.Knobs{
		NoUserConfig: true,
		NoDefaults:   true,
		NoGraphic:    true,
		Daemonize:    true,
		MemPrealloc:  q.config.MemPrealloc,
		HugePages:    q.config.HugePages,
		Realtime:     q.config.Realtime,
		Mlock:        q.config.Mlock,
	}

	kernel := cliQemu.Kernel{
		Path:   q.config.KernelPath,
		Params: strings.Join(q.kernelParams, " "),
	}

	rtc := cliQemu.RTC{
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

	qmpSockets := []cliQemu.QMPSocket{
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
	devices, err = q.appendImage(devices, podConfig)
	if err != nil {
		return err
	}

	cpuModel := "host"
	if q.nestedRun {
		cpuModel += ",pmu=off"
	}

	qemuConfig := cliQemu.Config{
		Name:        fmt.Sprintf("pod-%s", podConfig.ID),
		UUID:        q.forceUUIDFormat(podConfig.ID),
		Path:        q.path,
		Ctx:         q.qmpMonitorCh.ctx,
		Machine:     machine,
		SMP:         smp,
		Memory:      memory,
		Devices:     devices,
		CPUModel:    cpuModel,
		Kernel:      kernel,
		RTC:         rtc,
		QMPSockets:  qmpSockets,
		Knobs:       knobs,
		VGA:         "none",
		GlobalParam: "kvm-pit.lost_tick_policy=discard",
		Bios:        podConfig.HypervisorConfig.FirmwarePath,
	}

	q.qemuConfig = qemuConfig

	return nil
}

// startPod will start the Pod's VM.
func (q *qemu) startPod(startCh, stopCh chan struct{}) error {
	strErr, err := cliQemu.LaunchQemu(q.qemuConfig, newQMPLogger())
	if err != nil {
		return fmt.Errorf("%s", strErr)
	}

	// Start the QMP monitoring thread
	q.qmpMonitorCh.disconnectCh = stopCh
	q.qmpMonitorCh.wg.Add(1)
	q.qmpMonitor(startCh)

	return nil
}

// stopPod will stop the Pod's VM.
func (q *qemu) stopPod() error {
	cfg := cliQemu.QMPConfig{Logger: newQMPLogger()}
	q.qmpControlCh.disconnectCh = make(chan struct{})
	const timeout = time.Duration(10) * time.Second

	q.Logger().Info("Stopping Pod")
	qmp, _, err := cliQemu.QMPStart(q.qmpControlCh.ctx, q.qmpControlCh.path, cfg, q.qmpControlCh.disconnectCh)
	if err != nil {
		q.Logger().WithError(err).Error("Failed to connect to QEMU instance")
		return err
	}

	err = qmp.ExecuteQMPCapabilities(q.qmpMonitorCh.ctx)
	if err != nil {
		q.Logger().WithError(err).Error(qmpCapErrMsg)
		return err
	}

	if err := qmp.ExecuteQuit(q.qmpMonitorCh.ctx); err != nil {
		return err
	}

	// Wait for the VM disconnection notification
	select {
	case <-q.qmpControlCh.disconnectCh:
		break
	case <-time.After(timeout):
		return fmt.Errorf("Did not receive the VM disconnection notification (timeout %ds)", timeout)
	}

	return nil
}

func (q *qemu) togglePausePod(pause bool) error {
	defer func(qemu *qemu) {
		if q.qmpMonitorCh.qmp != nil {
			q.qmpMonitorCh.qmp.Shutdown()
		}
	}(q)

	cfg := cliQemu.QMPConfig{Logger: newQMPLogger()}

	// Auto-closed by QMPStart().
	disconnectCh := make(chan struct{})

	qmp, _, err := cliQemu.QMPStart(q.qmpControlCh.ctx, q.qmpControlCh.path, cfg, disconnectCh)
	if err != nil {
		q.Logger().WithError(err).Error("Failed to connect to QEMU instance")
		return err
	}

	q.qmpMonitorCh.qmp = qmp

	err = qmp.ExecuteQMPCapabilities(q.qmpMonitorCh.ctx)
	if err != nil {
		q.Logger().WithError(err).Error(qmpCapErrMsg)
		return err
	}

	if pause {
		err = q.qmpMonitorCh.qmp.ExecuteStop(q.qmpMonitorCh.ctx)
	} else {
		err = q.qmpMonitorCh.qmp.ExecuteCont(q.qmpMonitorCh.ctx)
	}

	if err != nil {
		return err
	}

	return nil
}

func (q *qemu) qmpSetup() (*cliQemu.QMP, error) {
	cfg := cliQemu.QMPConfig{Logger: newQMPLogger()}

	// Auto-closed by QMPStart().
	disconnectCh := make(chan struct{})

	qmp, _, err := cliQemu.QMPStart(q.qmpControlCh.ctx, q.qmpControlCh.path, cfg, disconnectCh)
	if err != nil {
		q.Logger().WithError(err).Error("Failed to connect to QEMU instance")
		return nil, err
	}

	err = qmp.ExecuteQMPCapabilities(q.qmpMonitorCh.ctx)
	if err != nil {
		q.Logger().WithError(err).Error(qmpCapErrMsg)
		return nil, err
	}

	return qmp, nil
}

func (q *qemu) hotplugBlockDevice(drive Drive, op operation) error {
	defer func(qemu *qemu) {
		if q.qmpMonitorCh.qmp != nil {
			q.qmpMonitorCh.qmp.Shutdown()
		}
	}(q)

	qmp, err := q.qmpSetup()
	if err != nil {
		return err
	}

	q.qmpMonitorCh.qmp = qmp

	devID := "virtio-" + drive.ID

	if op == addDevice {
		if err := q.qmpMonitorCh.qmp.ExecuteBlockdevAdd(q.qmpMonitorCh.ctx, drive.File, drive.ID); err != nil {
			return err
		}

		driver := "virtio-blk-pci"
		if err := q.qmpMonitorCh.qmp.ExecuteDeviceAdd(q.qmpMonitorCh.ctx, drive.ID, devID, driver, ""); err != nil {
			return err
		}
	} else {
		if err := q.qmpMonitorCh.qmp.ExecuteDeviceDel(q.qmpMonitorCh.ctx, devID); err != nil {
			return err
		}

		if err := q.qmpMonitorCh.qmp.ExecuteBlockdevDel(q.qmpMonitorCh.ctx, drive.ID); err != nil {
			return err
		}
	}

	return nil
}

func (q *qemu) hotplugDevice(devInfo interface{}, devType deviceType, op operation) error {
	switch devType {
	case blockDev:
		drive := devInfo.(Drive)
		return q.hotplugBlockDevice(drive, op)
	default:
		return fmt.Errorf("Only hotplug for block devices supported for now, provided device type : %v", devType)
	}
}

func (q *qemu) hotplugAddDevice(devInfo interface{}, devType deviceType) error {
	return q.hotplugDevice(devInfo, devType, addDevice)
}

func (q *qemu) hotplugRemoveDevice(devInfo interface{}, devType deviceType) error {
	return q.hotplugDevice(devInfo, devType, removeDevice)
}

func (q *qemu) pausePod() error {
	return q.togglePausePod(true)
}

func (q *qemu) resumePod() error {
	return q.togglePausePod(false)
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
	case netDev:
		endpoints := devInfo.([]Endpoint)
		q.qemuConfig.Devices = q.appendNetworks(q.qemuConfig.Devices, endpoints)
	case blockDev:
		drive := devInfo.(Drive)
		q.qemuConfig.Devices = q.appendBlockDevice(q.qemuConfig.Devices, drive)
	case vfioDev:
		vfDevice := devInfo.(VFIODevice)
		q.qemuConfig.Devices = q.appendVFIODevice(q.qemuConfig.Devices, vfDevice)
	default:
		break
	}

	return nil
}

// getPodConsole builds the path of the console where we can read
// logs coming from the pod.
func (q *qemu) getPodConsole(podID string) string {
	return filepath.Join(runStoragePath, podID, defaultConsole)
}
