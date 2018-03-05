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
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/sirupsen/logrus"
)

const cpBinaryName = "cp"

const fileMode0755 = os.FileMode(0755)

func fileCopy(srcPath, dstPath string) error {
	if srcPath == "" {
		return fmt.Errorf("Source path cannot be empty")
	}

	if dstPath == "" {
		return fmt.Errorf("Destination path cannot be empty")
	}

	binPath, err := exec.LookPath(cpBinaryName)
	if err != nil {
		return err
	}

	cmd := exec.Command(binPath, srcPath, dstPath)

	return cmd.Run()
}

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)

	if err != nil {
		return nil, err
	}

	return b, nil
}

func reverseString(s string) string {
	r := []rune(s)

	length := len(r)
	for i, j := 0, length-1; i < length/2; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}

	return string(r)
}

func cleanupFds(fds []*os.File, numFds int) {

	maxFds := len(fds)

	if numFds < maxFds {
		maxFds = numFds
	}

	for i := 0; i < maxFds; i++ {
		_ = fds[i].Close()
	}
}

// writeToFile opens a file in write only mode and writes bytes to it
func writeToFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY, fileMode0755)
	if err != nil {
		return err
	}

	defer f.Close()

	if _, err := f.Write(data); err != nil {
		return err
	}

	return nil
}

// Errorf is the same as fmt.Errorf() except that it creates an error object
// that also includes all available logging fields and details of where the
// error originated.
func Errorf(format string, args ...interface{}) error {
	now := time.Now().UTC()
	nano := now.Format(time.RFC3339Nano)

	// establish name of the _calling_ function!

	// at least 1 entry needed
	pc := make([]uintptr, 10)
	runtime.Callers(2, pc)
	fn := runtime.FuncForPC(pc[0])
	file, line := fn.FileLine(pc[0])

	// create a new error object
	err := fmt.Errorf(format, args...)

	buf := &bytes.Buffer{}

	logger := virtLog
	formatter := logger.Logger.Formatter
	out := logger.Logger.Out

	// cause subsequent log calls to save the log output
	logger.Logger.Out = buf

	// temporarily tweak log settings
	logger.Logger.Formatter = &logrus.TextFormatter{
		DisableColors:   true,
		TimestampFormat: time.RFC3339Nano,
	}

	// undo changed logger settings
	defer func() {
		logger.Logger.Formatter = formatter
		logger.Logger.Out = out
	}()

	// call the logger and save the output, including all the structured
	// fields and add some additional ones.
	logger.WithError(err).WithFields(logrus.Fields{
		"error-time": nano,
		"file":       fmt.Sprintf("%q", file),
		"line":       line,
		"function":   fn.Name(),
		"hello":      "world",
	}).Error()

	return errors.New(buf.String())
}
