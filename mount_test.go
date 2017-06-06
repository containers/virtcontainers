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
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestIsSystemMount(t *testing.T) {
	tests := []struct {
		mnt      string
		expected bool
	}{
		{"/sys", true},
		{"/sys/", true},
		{"/sys//", true},
		{"/sys/fs", true},
		{"/sys/fs/", true},
		{"/sys/fs/cgroup", true},
		{"/sysfoo", false},
		{"/home", false},
		{"/dev/block/", true},
	}

	for _, test := range tests {
		result := isSystemMount(test.mnt)
		if result != test.expected {
			t.Fatalf("Expected result for path %s : %v, got %v", test.mnt, test.expected, result)
		}
	}
}

func TestMajorMinorNumber(t *testing.T) {
	devices := []string{"/dev/zero", "/dev/net/tun"}

	for _, device := range devices {
		cmdStr := fmt.Sprintf("ls -l %s | awk '{print $5$6}'", device)
		cmd := exec.Command("sh", "-c", cmdStr)
		output, err := cmd.Output()

		if err != nil {
			t.Fatal(err)
		}

		data := bytes.Split(output, []byte(","))
		if len(data) < 2 {
			t.Fatal()
		}

		majorStr := strings.TrimSpace(string(data[0]))
		minorStr := strings.TrimSpace(string(data[1]))

		majorNo, err := strconv.Atoi(majorStr)
		minorNo, err := strconv.Atoi(minorStr)

		stat := syscall.Stat_t{}
		err = syscall.Stat(device, &stat)
		if err != nil {
			t.Fatal(err)
		}

		// Get major and minor numbers for the device itself. Note the use of stat.Rdev instead of Dev.
		major := major(stat.Rdev)
		minor := minor(stat.Rdev)

		if minor != minorNo {
			t.Fatalf("Expected minor number for device %s: %d, Got :%d", device, minorNo, minor)
		}

		if major != majorNo {
			t.Fatalf("Expected major number for device %s : %d, Got :%d", device, majorNo, major)
		}
	}
}

func TestGetDeviceForPathRoot(t *testing.T) {
	dev, err := getDeviceForPath("/")
	if err != nil {
		t.Fatal(err)
	}

	expected := "/"

	if dev.mountPoint != expected {
		t.Fatalf("Expected %s mountpoint, got %s", expected, dev.mountPoint)
	}
}

func TestGetDeviceForPathSuccess(t *testing.T) {
	dev, err := getDeviceForPath("/proc")
	if err != nil {
		t.Fatal(err)
	}

	expected := "/proc"

	if dev.mountPoint != expected {
		t.Fatalf("Expected %s mountpoint, got %s", expected, dev.mountPoint)
	}
}

func TestGetDeviceForPathEmptyPath(t *testing.T) {
	_, err := getDeviceForPath("")
	if err == nil {
		t.Fatal()
	}
}
