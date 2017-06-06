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
	"path/filepath"
	"syscall"
)

// These mounts need to be created by the agent within the VM
var systemMounts = []string{"/proc", "/dev", "/dev/pts", "/dev/shm", "/dev/mqueue", "/sys", "/sys/fs/cgroup"}

func major(dev uint64) int {
	return int((dev >> 8) & 0xfff)

}

func minor(dev uint64) int {
	return int((dev & 0xff) | ((dev >> 12) & 0xfff00))
}

type device struct {
	major      int
	minor      int
	mountPoint string
}

// getDeviceForPath gets the underlying device containing the file specified by path.
// The device type constitutes the major-minor number of the device and the dest mountPoint for the device
func getDeviceForPath(path string) (*device, error) {
	if path == "" {
		return &device{}, fmt.Errorf("Path cannot be empty")
	}

	stat := syscall.Stat_t{}
	err := syscall.Stat(path, &stat)
	if err != nil {
		return &device{}, err
	}

	// stat.Dev points to the underlying device containing the file
	major := major(stat.Dev)
	minor := minor(stat.Dev)

	mountPoint := path

	// We get the mount point by recursively peforming stat on the path
	// The point where the device changes indicates the mountpoint
	for {
		if mountPoint == "/" {
			break
		}

		parentStat := syscall.Stat_t{}
		parentDir := filepath.Dir(path)

		err := syscall.Lstat(parentDir, &parentStat)
		if err != nil {
			return &device{}, err
		}

		if parentStat.Dev != stat.Dev {
			break
		}

		mountPoint = parentDir
		stat = parentStat
		path = parentDir
	}

	dev := &device{
		major:      major,
		minor:      minor,
		mountPoint: mountPoint,
	}

	return dev, nil
}
