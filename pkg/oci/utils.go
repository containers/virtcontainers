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
	"io/ioutil"
	"path/filepath"
	"strconv"
	"strings"

	log "github.com/Sirupsen/logrus"
	vc "github.com/containers/virtcontainers"
	spec "github.com/opencontainers/runtime-spec/specs-go"
)

func cmdEnvs(spec spec.Spec, envs []vc.EnvVar) []vc.EnvVar {
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

// PodConfig converts an OCI compatible runtime configuration file
// to a virtcontainers pod configuration structure.
func PodConfig(bundlePath, cid, console string, interactive bool) (*vc.PodConfig, error) {
	log.Debugf("converting %s/config.json", bundlePath)

	configPath := filepath.Join(bundlePath, "config.json")
	configByte, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var ocispec spec.Spec
	if err = json.Unmarshal(configByte, &ocispec); err != nil {
		return nil, err
	}

	rootfs := filepath.Join(bundlePath, ocispec.Root.Path)

	cmd := vc.Cmd{
		Args:    ocispec.Process.Args,
		Envs:    cmdEnvs(ocispec, []vc.EnvVar{}),
		WorkDir: ocispec.Process.Cwd,
		User:    strconv.FormatUint(uint64(ocispec.Process.User.UID), 10),
		Group:   strconv.FormatUint(uint64(ocispec.Process.User.GID), 10),
	}

	containerConfig := vc.ContainerConfig{
		ID:          cid,
		RootFs:      rootfs,
		Interactive: interactive,
		Console:     console,
		Cmd:         cmd,
	}

	podConfig := vc.PodConfig{
		Containers: []vc.ContainerConfig{containerConfig},
	}

	return &podConfig, nil
}
