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

package oci

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Sirupsen/logrus"
	vc "github.com/containers/virtcontainers"
	spec "github.com/opencontainers/runtime-spec/specs-go"
)

var (
	// ErrNoLinux is an error for missing Linux sections in the OCI configuration file.
	ErrNoLinux = errors.New("missing Linux section")

	// ConfigPathKey is the annotation key to fetch the OCI configuration file path.
	ConfigPathKey = "com.github.containers.virtcontainers.pkg.oci.config_path"

	// BundlePathKey is the annotation key to fetch the OCI configuration file path.
	BundlePathKey = "com.github.containers.virtcontainers.pkg.oci.bundle_path"
)

// CompatOCIProcess is a structure inheriting from spec.Process defined
// in runtime-spec/specs-go package. The goal is to be compatible with
// both v1.0.0-rc4 and v1.0.0-rc5 since the latter introduced a change
// about the type of the Capabilities field.
// Refer to: https://github.com/opencontainers/runtime-spec/commit/37391fb
type CompatOCIProcess struct {
	spec.Process
	Capabilities interface{} `json:"capabilities,omitempty" platform:"linux"`
}

// CompatOCISpec is a structure inheriting from spec.Spec defined
// in runtime-spec/specs-go package. It relies on the CompatOCIProcess
// structure declared above, in order to be compatible with both
// v1.0.0-rc4 and v1.0.0-rc5.
// Refer to: https://github.com/opencontainers/runtime-spec/commit/37391fb
type CompatOCISpec struct {
	spec.Spec
	Process *CompatOCIProcess `json:"process,omitempty"`
}

// RuntimeConfig aggregates all runtime specific settings
type RuntimeConfig struct {
	VMConfig vc.Resources

	HypervisorType   vc.HypervisorType
	HypervisorConfig vc.HypervisorConfig

	AgentType   vc.AgentType
	AgentConfig interface{}

	ProxyType   vc.ProxyType
	ProxyConfig interface{}

	ShimType   vc.ShimType
	ShimConfig interface{}

	Console string
}

var ociLog = logrus.FieldLogger(logrus.New())

// SetLogger sets the logger for oci package.
func SetLogger(logger logrus.FieldLogger) {
	ociLog = logger
}

func cmdEnvs(spec CompatOCISpec, envs []vc.EnvVar) []vc.EnvVar {
	for _, env := range spec.Process.Env {
		kv := strings.Split(env, "=")
		if len(kv) < 2 {
			continue
		}

		envs = append(envs,
			vc.EnvVar{
				Var:   kv[0],
				Value: kv[1],
			})
	}

	return envs
}

func newHook(h spec.Hook) vc.Hook {
	timeout := 0
	if h.Timeout != nil {
		timeout = *h.Timeout
	}

	return vc.Hook{
		Path:    h.Path,
		Args:    h.Args,
		Env:     h.Env,
		Timeout: timeout,
	}
}

func containerHooks(spec CompatOCISpec) vc.Hooks {
	ociHooks := spec.Hooks
	if ociHooks == nil {
		return vc.Hooks{}
	}

	var hooks vc.Hooks

	for _, h := range ociHooks.Prestart {
		hooks.PreStartHooks = append(hooks.PreStartHooks, newHook(h))
	}

	for _, h := range ociHooks.Poststart {
		hooks.PostStartHooks = append(hooks.PostStartHooks, newHook(h))
	}

	for _, h := range ociHooks.Poststop {
		hooks.PostStopHooks = append(hooks.PostStopHooks, newHook(h))
	}

	return hooks
}

func newMount(m spec.Mount) vc.Mount {
	return vc.Mount{
		Source:      m.Source,
		Destination: m.Destination,
		Type:        m.Type,
		Options:     m.Options,
	}
}

func containerMounts(spec CompatOCISpec) []vc.Mount {
	ociMounts := spec.Spec.Mounts

	if ociMounts == nil {
		return []vc.Mount{}
	}

	var mnts []vc.Mount
	for _, m := range ociMounts {
		mnts = append(mnts, newMount(m))
	}

	return mnts
}

func networkConfig(ocispec CompatOCISpec) (vc.NetworkConfig, error) {
	linux := ocispec.Linux
	if linux == nil {
		return vc.NetworkConfig{}, ErrNoLinux
	}

	var netConf vc.NetworkConfig

	for _, n := range linux.Namespaces {
		if n.Type != spec.NetworkNamespace {
			continue
		}

		netConf.NumInterfaces = 1
		if n.Path != "" {
			netConf.NetNSPath = n.Path
		}
	}

	return netConf, nil
}

// PodConfig converts an OCI compatible runtime configuration file
// to a virtcontainers pod configuration structure.
func PodConfig(runtime RuntimeConfig, bundlePath, cid, console string) (*vc.PodConfig, *CompatOCISpec, error) {
	configPath := filepath.Join(bundlePath, "config.json")
	ociLog.Debugf("converting %s", configPath)

	configByte, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, nil, err
	}

	var ocispec CompatOCISpec
	if err = json.Unmarshal(configByte, &ocispec); err != nil {
		return nil, nil, err
	}

	rootfs := ocispec.Root.Path
	if !filepath.IsAbs(rootfs) {
		rootfs = filepath.Join(bundlePath, ocispec.Root.Path)
	}
	ociLog.Debugf("container rootfs: %s", rootfs)

	cmd := vc.Cmd{
		Args:         ocispec.Process.Args,
		Envs:         cmdEnvs(ocispec, []vc.EnvVar{}),
		WorkDir:      ocispec.Process.Cwd,
		User:         strconv.FormatUint(uint64(ocispec.Process.User.UID), 10),
		PrimaryGroup: strconv.FormatUint(uint64(ocispec.Process.User.GID), 10),
		Interactive:  ocispec.Process.Terminal,
		Console:      console,
	}

	cmd.SupplementaryGroups = []string{}
	for _, gid := range ocispec.Process.User.AdditionalGids {
		cmd.SupplementaryGroups = append(cmd.SupplementaryGroups, strconv.FormatUint(uint64(gid), 10))
	}

	containerConfig := vc.ContainerConfig{
		ID:             cid,
		RootFs:         rootfs,
		ReadonlyRootfs: ocispec.Spec.Root.Readonly,
		Cmd:            cmd,
		Annotations: map[string]string{
			ConfigPathKey: configPath,
			BundlePathKey: bundlePath,
		},
		Mounts: containerMounts(ocispec),
	}

	networkConfig, err := networkConfig(ocispec)
	if err != nil {
		return nil, nil, err
	}

	podConfig := vc.PodConfig{
		ID: cid,

		Hooks: containerHooks(ocispec),

		VMConfig: runtime.VMConfig,

		HypervisorType:   runtime.HypervisorType,
		HypervisorConfig: runtime.HypervisorConfig,

		AgentType:   runtime.AgentType,
		AgentConfig: runtime.AgentConfig,

		ProxyType:   runtime.ProxyType,
		ProxyConfig: runtime.ProxyConfig,

		ShimType:   runtime.ShimType,
		ShimConfig: runtime.ShimConfig,

		NetworkModel:  vc.CNMNetworkModel,
		NetworkConfig: networkConfig,

		Containers: []vc.ContainerConfig{containerConfig},

		Annotations: map[string]string{
			ConfigPathKey: configPath,
			BundlePathKey: bundlePath,
		},
	}

	return &podConfig, &ocispec, nil
}

// StatusToOCIState translates a virtcontainers pod status into an OCI state.
func StatusToOCIState(status vc.PodStatus) (spec.State, error) {
	if len(status.ContainersStatus) != 1 {
		return spec.State{},
			fmt.Errorf("ContainerStatus list from PodStatus is wrong, expecting only one container status, got %v",
				status.ContainersStatus)
	}

	state := spec.State{
		Version:     spec.Version,
		ID:          status.ID,
		Status:      stateToOCIState(status.ContainersStatus[0].State),
		Pid:         status.ContainersStatus[0].PID,
		Bundle:      status.ContainersStatus[0].Annotations[BundlePathKey],
		Annotations: status.ContainersStatus[0].Annotations,
	}

	return state, nil
}

func stateToOCIState(state vc.State) string {
	switch state.State {
	case vc.StateReady:
		return "created"
	case vc.StateRunning:
		return "running"
	case vc.StateStopped:
		return "stopped"
	default:
		return ""
	}
}

// EnvVars converts an OCI process environment variables slice
// into a virtcontainers EnvVar slice.
func EnvVars(envs []string) ([]vc.EnvVar, error) {
	var envVars []vc.EnvVar

	envDelimiter := "="
	expectedEnvLen := 2

	for _, env := range envs {
		envSlice := strings.SplitN(env, envDelimiter, expectedEnvLen)

		if len(envSlice) < expectedEnvLen {
			return []vc.EnvVar{}, fmt.Errorf("Wrong string format: %s, expecting only %v parameters separated with %q",
				env, expectedEnvLen, envDelimiter)
		}

		if envSlice[0] == "" {
			return []vc.EnvVar{}, fmt.Errorf("Environment variable cannot be empty")
		}

		envSlice[1] = strings.Trim(envSlice[1], "' ")

		if envSlice[1] == "" {
			return []vc.EnvVar{}, fmt.Errorf("Environment value cannot be empty")
		}

		envVar := vc.EnvVar{
			Var:   envSlice[0],
			Value: envSlice[1],
		}

		envVars = append(envVars, envVar)
	}

	return envVars, nil
}

// PodToOCIConfig returns an OCI spec configuration from the annotation
// stored into the pod.
func PodToOCIConfig(pod vc.Pod) (CompatOCISpec, error) {
	ociConfigPath, err := pod.Annotations(ConfigPathKey)
	if err != nil {
		return CompatOCISpec{}, err
	}

	data, err := ioutil.ReadFile(ociConfigPath)
	if err != nil {
		return CompatOCISpec{}, err
	}

	var ociSpec CompatOCISpec
	if err := json.Unmarshal(data, &ociSpec); err != nil {
		return CompatOCISpec{}, err
	}

	return ociSpec, nil
}
