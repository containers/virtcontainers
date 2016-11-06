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

	"github.com/golang/glog"
	"github.com/urfave/cli"

	vc "github.com/sameo/virtcontainers"
)

var podConfigFlags = []cli.Flag{
	cli.StringFlag{
		Name:  "console",
		Value: "",
		Usage: "the container console",
	},

	cli.StringFlag{
		Name:  "bundle",
		Value: "",
		Usage: "the container bundle",
	},

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

	cli.StringFlag{
		Name:  "init-cmd",
		Value: "echo",
		Usage: "the initial command to run on pod containers",
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

	console := context.String("console")
	bundle := context.String("bundle")
	sshdUser := context.String("sshd-user")
	sshdServer := context.String("sshd-server")
	sshdPort := context.String("sshd-port")
	sshdKey := context.String("sshd-auth-file")
	hyperCtlSockName := context.String("hyper-ctl-sock-name")
	hyperTtySockName := context.String("hyper-tty-sock-name")
	initCmd := context.String("init-cmd")
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

	interactive := false
	if console != "" {
		interactive = true
	}

	envs := []vc.EnvVar{
		{
			Var:   "PATH",
			Value: "/bin:/usr/bin:/sbin:/usr/sbin",
		},
	}

	cmd := vc.Cmd{
		Args:    strings.Split(initCmd, " "),
		Envs:    envs,
		WorkDir: "/",
	}

	container := vc.ContainerConfig{
		ID:          "1",
		RootFs:      bundle,
		Interactive: interactive,
		Console:     console,
		Cmd:         cmd,
	}

	containers := []vc.ContainerConfig{
		container,
	}

	hypervisorConfig := vc.HypervisorConfig{
		KernelPath:     "/usr/share/clear-containers/vmlinux.container",
		ImagePath:      "/usr/share/clear-containers/clear-containers.img",
		HypervisorPath: "/usr/bin/qemu-lite-system-x86_64",
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
			SockCtlName: hyperCtlSockName,
			SockTtyName: hyperTtySockName,
			Volumes:     *volumes,
			Sockets:     *sockets,
		}
	default:
		agConfig = nil
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

		Containers: containers,
	}

	return podConfig, nil
}

func runPod(context *cli.Context) error {
	podConfig, err := buildPodConfig(context)
	if err != nil {
		return fmt.Errorf("Could not build pod config: %s\n", err)
	}

	_, err = vc.RunPod(podConfig)
	if err != nil {
		return fmt.Errorf("Could not run pod: %s\n", err)
	}

	return nil
}

func createPod(context *cli.Context) error {
	podConfig, err := buildPodConfig(context)
	if err != nil {
		return fmt.Errorf("Could not build pod config: %s\n", err)
	}

	p, err := vc.CreatePod(podConfig)
	if err != nil {
		return fmt.Errorf("Could not create pod: %s\n", err)
	}

	fmt.Printf("Created pod %s\n", p.ID())

	return nil
}

func deletePod(context *cli.Context) error {
	_, err := vc.DeletePod(context.String("id"))
	if err != nil {
		return fmt.Errorf("Could not delete pod: %s\n", err)
	}

	return nil
}

func startPod(context *cli.Context) error {
	_, err := vc.StartPod(context.String("id"))
	if err != nil {
		return fmt.Errorf("Could not delete pod: %s\n", err)
	}

	return nil
}

func stopPod(context *cli.Context) error {
	_, err := vc.StopPod(context.String("id"))
	if err != nil {
		return fmt.Errorf("Could not stop pod: %s\n", err)
	}

	return nil
}

func listPods(context *cli.Context) error {
	err := vc.ListPod()
	if err != nil {
		return fmt.Errorf("Could not list pod: %s\n", err)
	}

	return nil
}

func statusPod(context *cli.Context) error {
	err := vc.StatusPod(context.String("id"))
	if err != nil {
		return fmt.Errorf("Could not get pod status: %s\n", err)
	}

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

func main() {
	flag.Parse()

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
	}

	err := virtc.Run(os.Args)
	if err != nil {
		glog.Fatal(err)
	}
}
