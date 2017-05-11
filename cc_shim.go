//
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
//

package virtcontainers

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

type ccShim struct{}

// CCShimConfig is the structure providing specific configuration
// for ccShim implementation.
type CCShimConfig struct {
	Path string
}

var consoleFileMode = os.FileMode(0660)

// start is the ccShim start implementation.
// It starts the cc-shim binary with URL and token flags provided by
// the proxy.
// If lockFile is not an empty string it creates and locks the lockFile before
// start the shim therefore lockFile is inherited by the shim
func (s *ccShim) start(pod Pod, lockFile string, params ShimParams) (int, error) {
	if pod.config == nil {
		return -1, fmt.Errorf("Pod config cannot be nil")
	}

	config, ok := newShimConfig(*(pod.config)).(CCShimConfig)
	if !ok {
		return -1, fmt.Errorf("Wrong shim config type, should be CCShimConfig type")
	}

	if config.Path == "" {
		return -1, fmt.Errorf("Shim path cannot be empty")
	}

	if params.Token == "" {
		return -1, fmt.Errorf("Token cannot be empty")
	}

	if params.URL == "" {
		return -1, fmt.Errorf("URL cannot be empty")
	}

	cmd := exec.Command(config.Path, "-t", params.Token, "-u", params.URL)
	cmd.Env = os.Environ()

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	var f *os.File
	var err error
	if params.Console != "" {
		f, err = os.OpenFile(params.Console, os.O_RDWR, consoleFileMode)
		if err != nil {
			return -1, err
		}

		cmd.Stdin = f
		cmd.Stdout = f
		cmd.Stderr = f
	}
	defer func() {
		if f != nil {
			f.Close()
		}
	}()

	if lockFile != "" {
		//Create lockFile
		f, err := os.OpenFile(lockFile, os.O_RDONLY|os.O_CREATE, 0600)
		if err != nil {
			return -1, err
		}
		defer f.Close()

		// Locks lockFile
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
		if err != nil {
			return -1, err
		}

		//Do not close lockFile on exec
		cmd.ExtraFiles = append(cmd.ExtraFiles, f)
	}

	if err := cmd.Start(); err != nil {
		return -1, err
	}

	return cmd.Process.Pid, nil
}
