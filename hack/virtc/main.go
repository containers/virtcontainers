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

package main

import (
	"flag"
	"fmt"
	"os"
	"os/user"
	"strings"
	"text/tabwriter"

	"github.com/golang/glog"
	"github.com/urfave/cli"

	vc "github.com/containers/virtcontainers"
)

var listFormat = "%s\t%s\t%s\t%s\n"
var statusFormat = "%s\t%s\n"

var podConfigFlags = []cli.Flag{
	cli.GenericFlag{
		Name:  "agent",
		Value: new(vc.AgentType),
		Usage: "the guest agent",
	},

	cli.GenericFlag{
		Name:  "spawner",
		Value: new(vc.SpawnerType),
		Usage: "the guest spawner",
	},

	cli.GenericFlag{
		Name:  "network",
		Value: new(vc.NetworkModel),
		Usage: "the network model",
	},

	cli.GenericFlag{
		Name:  "proxy",
		Value: new(vc.ProxyType),
		Usage: "the agent's proxy",
	},

	cli.StringFlag{
		Name:  "proxy-sock",
		Value: "",
		Usage: "the agent's proxy socket path",
	},

	cli.StringFlag{
		Name:  "sshd-user",
		Value: "",
		Usage: "the sshd user",
	},

	cli.StringFlag{
		Name:  "sshd-auth-file",
		Value: "",
		Usage: "the sshd private key path",
	},

	cli.StringFlag{
		Name:  "sshd-server",
		Value: "",
		Usage: "the sshd server",
	},

	cli.StringFlag{
		Name:  "sshd-port",
		Value: "",
		Usage: "the sshd server port",
	},

	cli.StringFlag{
		Name:  "hyper-ctl-sock-name",
		Value: "",
		Usage: "the hyperstart control socket name",
	},

	cli.StringFlag{
		Name:  "hyper-tty-sock-name",
		Value: "",
		Usage: "the hyperstart tty socket name",
	},

	cli.StringFlag{
		Name:  "pause-path",
		Value: "",
		Usage: "the hyperstart path to pause binary",
	},

	cli.GenericFlag{
		Name:  "volume",
		Value: new(vc.Volumes),
		Usage: "the volume to be shared with VM",
	},

	cli.GenericFlag{
		Name:  "socket",
		Value: new(vc.Sockets),
		Usage: "the socket list to be shared with VM",
	},

	cli.UintFlag{
		Name:  "cpus",
		Value: 0,
		Usage: "the number of virtual cpus available for this pod",
	},

	cli.UintFlag{
		Name:  "memory",
		Value: 0,
		Usage: "the amount of memory available for this pod in MiB",
	},
}

func buildPodConfig(context *cli.Context) (vc.PodConfig, error) {
	var agConfig interface{}
	var proxyConfig interface{}

	sshdUser := context.String("sshd-user")
	sshdServer := context.String("sshd-server")
	sshdPort := context.String("sshd-port")
	sshdKey := context.String("sshd-auth-file")
	hyperCtlSockName := context.String("hyper-ctl-sock-name")
	hyperTtySockName := context.String("hyper-tty-sock-name")
	hyperPauseBinPath := context.String("pause-path")
	proxyRuntimeSocket := context.String("proxy-sock")
	vmVCPUs := context.Uint("vm-vcpus")
	vmMemory := context.Uint("vm-memory")
	agentType, ok := context.Generic("agent").(*vc.AgentType)
	if ok != true {
		return vc.PodConfig{}, fmt.Errorf("Could not convert agent type")
	}

	spawnerType, ok := context.Generic("spawner").(*vc.SpawnerType)
	if ok != true {
		return vc.PodConfig{}, fmt.Errorf("Could not convert spawner type")
	}

	networkModel, ok := context.Generic("network").(*vc.NetworkModel)
	if ok != true {
		return vc.PodConfig{}, fmt.Errorf("Could not convert network model")
	}

	proxyType, ok := context.Generic("proxy").(*vc.ProxyType)
	if ok != true {
		return vc.PodConfig{}, fmt.Errorf("Could not convert proxy type")
	}

	volumes, ok := context.Generic("volume").(*vc.Volumes)
	if ok != true {
		return vc.PodConfig{}, fmt.Errorf("Could not convert to volume list")
	}

	sockets, ok := context.Generic("socket").(*vc.Sockets)
	if ok != true {
		return vc.PodConfig{}, fmt.Errorf("Could not convert to socket list")
	}

	u, _ := user.Current()
	if sshdUser == "" {
		sshdUser = u.Username
	}

	hypervisorConfig := vc.HypervisorConfig{
		KernelPath:     "/usr/share/clear-containers/vmlinux.container",
		ImagePath:      "/usr/share/clear-containers/clear-containers.img",
		HypervisorPath: "/usr/bin/qemu-lite-system-x86_64",
	}

	netConfig := vc.NetworkConfig{
		NumInterfaces: 1,
	}

	switch *agentType {
	case vc.SSHdAgent:
		agConfig = vc.SshdConfig{
			Username:    sshdUser,
			PrivKeyFile: sshdKey,
			Server:      sshdServer,
			Port:        sshdPort,
			Protocol:    "tcp",
			Spawner:     *spawnerType,
		}
	case vc.HyperstartAgent:
		agConfig = vc.HyperConfig{
			SockCtlName:  hyperCtlSockName,
			SockTtyName:  hyperTtySockName,
			Volumes:      *volumes,
			Sockets:      *sockets,
			PauseBinPath: hyperPauseBinPath,
		}
	default:
		agConfig = nil
	}

	switch *proxyType {
	case vc.CCProxyType:
		proxyConfig = vc.CCProxyConfig{
			RuntimeSocketPath: proxyRuntimeSocket,
		}

	default:
		proxyConfig = nil
	}

	vmConfig := vc.Resources{
		VCPUs:  vmVCPUs,
		Memory: vmMemory,
	}

	podConfig := vc.PodConfig{
		VMConfig: vmConfig,

		HypervisorType:   vc.QemuHypervisor,
		HypervisorConfig: hypervisorConfig,

		AgentType:   *agentType,
		AgentConfig: agConfig,

		NetworkModel:  *networkModel,
		NetworkConfig: netConfig,

		ProxyType:   *proxyType,
		ProxyConfig: proxyConfig,

		Containers: []vc.ContainerConfig{},
	}

	return podConfig, nil
}

func runPod(context *cli.Context) error {
	podConfig, err := buildPodConfig(context)
	if err != nil {
		return fmt.Errorf("Could not build pod config: %s", err)
	}

	_, err = vc.RunPod(podConfig)
	if err != nil {
		return fmt.Errorf("Could not run pod: %s", err)
	}

	return nil
}

func createPod(context *cli.Context) error {
	podConfig, err := buildPodConfig(context)
	if err != nil {
		return fmt.Errorf("Could not build pod config: %s", err)
	}

	p, err := vc.CreatePod(podConfig)
	if err != nil {
		return fmt.Errorf("Could not create pod: %s", err)
	}

	fmt.Printf("Created pod %s\n", p.ID())

	return nil
}

func deletePod(context *cli.Context) error {
	_, err := vc.DeletePod(context.String("id"))
	if err != nil {
		return fmt.Errorf("Could not delete pod: %s", err)
	}

	return nil
}

func startPod(context *cli.Context) error {
	_, err := vc.StartPod(context.String("id"))
	if err != nil {
		return fmt.Errorf("Could not start pod: %s", err)
	}

	return nil
}

func stopPod(context *cli.Context) error {
	_, err := vc.StopPod(context.String("id"))
	if err != nil {
		return fmt.Errorf("Could not stop pod: %s", err)
	}

	return nil
}

func listPods(context *cli.Context) error {
	podStatusList, err := vc.ListPod()
	if err != nil {
		return fmt.Errorf("Could not list pod: %s", err)
	}

	w := tabwriter.NewWriter(os.Stdout, 2, 8, 1, '\t', 0)
	fmt.Fprintf(w, listFormat, "POD ID", "STATE", "HYPERVISOR", "AGENT")

	for _, podStatus := range podStatusList {
		fmt.Fprintf(w, listFormat,
			podStatus.ID, podStatus.State.State, podStatus.Hypervisor, podStatus.Agent)
	}

	w.Flush()

	return nil
}

func statusPod(context *cli.Context) error {
	podStatus, err := vc.StatusPod(context.String("id"))
	if err != nil {
		return fmt.Errorf("Could not get pod status: %s", err)
	}

	w := tabwriter.NewWriter(os.Stdout, 2, 8, 1, '\t', 0)
	fmt.Fprintf(w, listFormat, "POD ID", "STATE", "HYPERVISOR", "AGENT")

	fmt.Fprintf(w, listFormat+"\n",
		podStatus.ID, podStatus.State.State, podStatus.Hypervisor, podStatus.Agent)

	fmt.Fprintf(w, statusFormat, "CONTAINER ID", "STATE")

	for _, contStatus := range podStatus.ContainersStatus {
		fmt.Fprintf(w, statusFormat, contStatus.ID, contStatus.State.State)
	}

	w.Flush()

	return nil
}

var runPodCommand = cli.Command{
	Name:  "run",
	Usage: "run a pod",
	Flags: podConfigFlags,
	Action: func(context *cli.Context) error {
		return runPod(context)
	},
}

var createPodCommand = cli.Command{
	Name:  "create",
	Usage: "create a pod",
	Flags: podConfigFlags,
	Action: func(context *cli.Context) error {
		return createPod(context)
	},
}

var deletePodCommand = cli.Command{
	Name:  "delete",
	Usage: "delete an existing pod",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "id",
			Value: "",
			Usage: "the pod identifier",
		},
	},
	Action: func(context *cli.Context) error {
		return deletePod(context)
	},
}

var startPodCommand = cli.Command{
	Name:  "start",
	Usage: "start an existing pod",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "id",
			Value: "",
			Usage: "the pod identifier",
		},
	},
	Action: func(context *cli.Context) error {
		return startPod(context)
	},
}

var stopPodCommand = cli.Command{
	Name:  "stop",
	Usage: "stop an existing pod",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "id",
			Value: "",
			Usage: "the pod identifier",
		},
	},
	Action: func(context *cli.Context) error {
		return stopPod(context)
	},
}

var listPodsCommand = cli.Command{
	Name:  "list",
	Usage: "list all existing pods",
	Action: func(context *cli.Context) error {
		return listPods(context)
	},
}

var statusPodCommand = cli.Command{
	Name:  "status",
	Usage: "returns a detailed pod status",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "id",
			Value: "",
			Usage: "the pod identifier",
		},
	},
	Action: func(context *cli.Context) error {
		return statusPod(context)
	},
}

func createContainer(context *cli.Context) error {
	console := context.String("console")

	envs := []vc.EnvVar{
		{
			Var:   "PATH",
			Value: "/bin:/usr/bin:/sbin:/usr/sbin",
		},
	}

	cmd := vc.Cmd{
		Args:    strings.Split(context.String("cmd"), " "),
		Envs:    envs,
		WorkDir: "/",
	}

	interactive := false
	if console != "" {
		interactive = true
	}

	containerConfig := vc.ContainerConfig{
		ID:          context.String("id"),
		RootFs:      context.String("rootfs"),
		Interactive: interactive,
		Console:     console,
		Cmd:         cmd,
	}

	c, err := vc.CreateContainer(context.String("pod-id"), containerConfig)
	if err != nil {
		return fmt.Errorf("Could not create container: %s", err)
	}

	fmt.Printf("Created container %s\n", c.ID())

	return nil
}

func deleteContainer(context *cli.Context) error {
	c, err := vc.DeleteContainer(context.String("pod-id"), context.String("id"))
	if err != nil {
		return fmt.Errorf("Could not delete container: %s", err)
	}

	fmt.Printf("Container %s deleted\n", c.ID())

	return nil
}

func startContainer(context *cli.Context) error {
	c, err := vc.StartContainer(context.String("pod-id"), context.String("id"))
	if err != nil {
		return fmt.Errorf("Could not start container: %s", err)
	}

	fmt.Printf("Container %s started\n", c.ID())

	return nil
}

func stopContainer(context *cli.Context) error {
	c, err := vc.StopContainer(context.String("pod-id"), context.String("id"))
	if err != nil {
		return fmt.Errorf("Could not stop container: %s", err)
	}

	fmt.Printf("Container %s stopped\n", c.ID())

	return nil
}

func enterContainer(context *cli.Context) error {
	envs := []vc.EnvVar{
		{
			Var:   "PATH",
			Value: "/bin:/usr/bin:/sbin:/usr/sbin",
		},
	}

	cmd := vc.Cmd{
		Args:    strings.Split(context.String("cmd"), " "),
		Envs:    envs,
		WorkDir: "/",
	}

	c, err := vc.EnterContainer(context.String("pod-id"), context.String("id"), cmd)
	if err != nil {
		return fmt.Errorf("Could not enter container: %s", err)
	}

	fmt.Printf("Container %s entered\n", c.ID())

	return nil
}

func statusContainer(context *cli.Context) error {
	contStatus, err := vc.StatusContainer(context.String("pod-id"), context.String("id"))
	if err != nil {
		return fmt.Errorf("Could not get container status: %s", err)
	}

	w := tabwriter.NewWriter(os.Stdout, 2, 8, 1, '\t', 0)
	fmt.Fprintf(w, statusFormat, "CONTAINER ID", "STATE")
	fmt.Fprintf(w, statusFormat, contStatus.ID, contStatus.State.State)

	w.Flush()

	return nil
}

var createContainerCommand = cli.Command{
	Name:  "create",
	Usage: "create a container",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "id",
			Value: "",
			Usage: "the container identifier",
		},
		cli.StringFlag{
			Name:  "pod-id",
			Value: "",
			Usage: "the pod identifier",
		},
		cli.StringFlag{
			Name:  "rootfs",
			Value: "",
			Usage: "the container rootfs directory",
		},
		cli.StringFlag{
			Name:  "cmd",
			Value: "",
			Usage: "the command executed inside the container",
		},
		cli.StringFlag{
			Name:  "console",
			Value: "",
			Usage: "the container console",
		},
	},
	Action: func(context *cli.Context) error {
		return createContainer(context)
	},
}

var deleteContainerCommand = cli.Command{
	Name:  "delete",
	Usage: "delete an existing container",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "id",
			Value: "",
			Usage: "the container identifier",
		},
		cli.StringFlag{
			Name:  "pod-id",
			Value: "",
			Usage: "the pod identifier",
		},
	},
	Action: func(context *cli.Context) error {
		return deleteContainer(context)
	},
}

var startContainerCommand = cli.Command{
	Name:  "start",
	Usage: "start an existing container",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "id",
			Value: "",
			Usage: "the container identifier",
		},
		cli.StringFlag{
			Name:  "pod-id",
			Value: "",
			Usage: "the pod identifier",
		},
	},
	Action: func(context *cli.Context) error {
		return startContainer(context)
	},
}

var stopContainerCommand = cli.Command{
	Name:  "stop",
	Usage: "stop an existing container",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "id",
			Value: "",
			Usage: "the container identifier",
		},
		cli.StringFlag{
			Name:  "pod-id",
			Value: "",
			Usage: "the pod identifier",
		},
	},
	Action: func(context *cli.Context) error {
		return stopContainer(context)
	},
}

var enterContainerCommand = cli.Command{
	Name:  "enter",
	Usage: "enter an existing container",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "id",
			Value: "",
			Usage: "the container identifier",
		},
		cli.StringFlag{
			Name:  "pod-id",
			Value: "",
			Usage: "the pod identifier",
		},
		cli.StringFlag{
			Name:  "cmd",
			Value: "echo",
			Usage: "the command executed inside the container",
		},
	},
	Action: func(context *cli.Context) error {
		return enterContainer(context)
	},
}

var statusContainerCommand = cli.Command{
	Name:  "status",
	Usage: "returns detailed container status",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "id",
			Value: "",
			Usage: "the container identifier",
		},
		cli.StringFlag{
			Name:  "pod-id",
			Value: "",
			Usage: "the pod identifier",
		},
	},
	Action: func(context *cli.Context) error {
		return statusContainer(context)
	},
}

func glogFlagShim(fakeVals map[string]string) {
	flag.VisitAll(func(fl *flag.Flag) {
		if val, ok := fakeVals[fl.Name]; ok {
			fl.Value.Set(val)
		}
	})
}

func glogShim(c *cli.Context) {
	_ = flag.CommandLine.Parse([]string{})
	glogFlagShim(map[string]string{
		"v":                fmt.Sprint(c.Int("v")),
		"logtostderr":      fmt.Sprint(c.Bool("logtostderr")),
		"stderrthreshold":  fmt.Sprint(c.Int("stderrthreshold")),
		"alsologtostderr":  fmt.Sprint(c.Bool("alsologtostderr")),
		"vmodule":          c.String("vmodule"),
		"log_dir":          c.String("log_dir"),
		"log_backtrace_at": c.String("log_backtrace_at"),
	})
}

var glogFlags = []cli.Flag{
	cli.IntFlag{
		Name: "v", Value: 0, Usage: "log level for V logs",
	},
	cli.BoolFlag{
		Name: "logtostderr", Usage: "log to standard error instead of files",
	},
	cli.IntFlag{
		Name:  "stderrthreshold",
		Usage: "logs at or above this threshold go to stderr",
	},
	cli.BoolFlag{
		Name: "alsologtostderr", Usage: "log to standard error as well as files",
	},
	cli.StringFlag{
		Name:  "vmodule",
		Usage: "comma-separated list of pattern=N settings for file-filtered logging",
	},
	cli.StringFlag{
		Name: "log_dir", Usage: "If non-empty, write log files in this directory",
	},
	cli.StringFlag{
		Name:  "log_backtrace_at",
		Usage: "when logging hits line file:N, emit a stack trace",
		Value: ":0",
	},
}

func main() {
	flag.Parse()

	cli.VersionFlag = cli.BoolFlag{
		Name:  "version",
		Usage: "print the version",
	}

	virtc := cli.NewApp()
	virtc.Name = "VirtContainers CLI"
	virtc.Version = "0.0.1"

	virtc.Commands = []cli.Command{
		{
			Name:  "pod",
			Usage: "pod commands",
			Subcommands: []cli.Command{
				createPodCommand,
				deletePodCommand,
				listPodsCommand,
				runPodCommand,
				startPodCommand,
				stopPodCommand,
				statusPodCommand,
			},
		},
		{
			Name:  "container",
			Usage: "container commands",
			Subcommands: []cli.Command{
				createContainerCommand,
				deleteContainerCommand,
				startContainerCommand,
				stopContainerCommand,
				enterContainerCommand,
				statusContainerCommand,
			},
		},
	}

	virtc.Flags = append(virtc.Flags, glogFlags...)
	virtc.Action = func(c *cli.Context) error {
		glogShim(c)
		return nil
	}

	err := virtc.Run(os.Args)
	if err != nil {
		glog.Fatal(err)
	}
}
