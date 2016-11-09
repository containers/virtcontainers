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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/golang/glog"
)

// ContainerConfig describes one container runtime configuration.
type ContainerConfig struct {
	ID string

	// RootFs is the container workload image on the host.
	RootFs string

	// Interactive specifies if the container runs in the foreground.
	Interactive bool

	// Console is a console path provided by the caller.
	Console string

	// Cmd specifies the command to run on a container
	Cmd Cmd
}

// valid checks that the container configuration is valid.
func (containerConfig *ContainerConfig) valid() bool {
	if containerConfig.ID == "" {
		return false
	}

	return true
}

// storeContainerConfig is the storage container configuration storage implementation for filesystem.
func (fs *filesystem) storeContainerConfig(podID string, config ContainerConfig) error {
	if config.valid() == false {
		return fmt.Errorf("Invalid container configuration")
	}

	cPath := filepath.Join(podID, config.ID)
	podConfigFile, err := podFile(cPath, configFileType)
	if err != nil {
		return err
	}

	_, err = os.Stat(podConfigFile)
	if err == nil {
		os.Remove(podConfigFile)
	}

	f, err := os.Create(podConfigFile)
	if err != nil {
		return err
	}
	defer f.Close()

	jsonOut, err := json.Marshal(config)
	if err != nil {
		glog.Errorf("Could not marshall pod config: %s\n", err)
		return err
	}
	f.Write(jsonOut)

	return nil
}

// fetchContainerConfig is the storage container configuration retrieval implementation for filesystem.
func (fs *filesystem) fetchContainerConfig(containerPath string) (ContainerConfig, error) {
	var config ContainerConfig

	podConfigFile, err := podFile(containerPath, configFileType)
	if err != nil {
		return config, err
	}

	_, err = os.Stat(podConfigFile)
	if err != nil {
		return config, err
	}

	fileData, err := ioutil.ReadFile(podConfigFile)
	if err != nil {
		return config, err
	}

	err = json.Unmarshal([]byte(string(fileData)), &config)
	if err != nil {
		return config, err
	}

	return config, nil
}

// Container is composed of a set of containers and a runtime environment.
// A Container can be created, deleted, started, stopped, listed, entered, paused and restored.
type Container struct {
	id    string
	podID string

	rootFs string

	config *ContainerConfig

	pod *Pod

	runPath       string
	configPath    string
	containerPath string

	state State

	lockFile *os.File
}

// ID returns the container identifier string.
func (c *Container) ID() string {
	return c.id
}

// fetchContainer fetches a container config from a pod ID and returns a Container.
func fetchContainer(pod *Pod, containerID string) (*Container, error) {
	fs := filesystem{}
	cPath := filepath.Join(pod.id, containerID)
	config, err := fs.fetchContainerConfig(cPath)
	if err != nil {
		return nil, err
	}

	glog.Infof("Info structure:\n%+v\n", config)

	return createContainer(pod, config)
}

// storeContainer stores a container config.
func (c *Container) storeContainer() error {
	fs := filesystem{}
	err := fs.storeContainerConfig(c.pod.id, *(c.config))
	if err != nil {
		return err
	}

	return nil
}

func (c *Container) setContainerState(state stateString) error {
	c.state = State{
		State: state,
	}

	err := c.pod.storage.storeState(c.containerPath, c.state)
	if err != nil {
		return err
	}

	return nil
}

func (c *Container) createContainersDirs() error {
	err := os.MkdirAll(c.runPath, os.ModeDir)
	if err != nil {
		return err
	}

	err = os.MkdirAll(c.configPath, os.ModeDir)
	if err != nil {
		c.pod.storage.delete(c.containerPath, nil)
		return err
	}

	return nil
}

func createContainer(pod *Pod, contConfig ContainerConfig) (*Container, error) {
	c := &Container{
		id:            contConfig.ID,
		rootFs:        contConfig.RootFs,
		config:        &contConfig,
		pod:           pod,
		runPath:       filepath.Join(runStoragePath, pod.id, contConfig.ID),
		configPath:    filepath.Join(configStoragePath, pod.id, contConfig.ID),
		containerPath: filepath.Join(pod.id, contConfig.ID),
		state:         State{},
	}

	err := c.createContainersDirs()
	if err != nil {
		return nil, err
	}

	state, err := c.pod.storage.fetchState(c.containerPath)
	if err == nil && state.State != "" {
		c.state.State = state.State
		return c, nil
	}

	err = c.pod.setContainerState(c.id, stateReady)
	if err != nil {
		return nil, err
	}

	return c, nil
}

func (c *Container) delete() error {
	if c.state.State != stateReady {
		return fmt.Errorf("Pod not ready, impossible to delete")
	}

	err := c.pod.storage.delete(c.containerPath, nil)
	if err != nil {
		return err
	}

	return nil
}

func (c *Container) start() error {
	state, err := c.pod.storage.fetchState(c.pod.id)
	if err != nil {
		return err
	}

	if state.State != stateRunning {
		return fmt.Errorf("Pod not running, impossible to start the container")
	}

	state, err = c.pod.storage.fetchState(c.containerPath)
	if err != nil {
		return err
	}

	if state.State != stateReady {
		return fmt.Errorf("Container not ready, impossible to start")
	}

	err = state.validTransition(stateReady, stateRunning)
	if err != nil {
		return err
	}

	err = c.pod.agent.startAgent()
	if err != nil {
		return err
	}

	err = c.pod.agent.startContainer(*(c.pod.config), *(c.config))
	if err != nil {
		c.stop()
		return err
	}

	err = c.setContainerState(stateRunning)
	if err != nil {
		return err
	}

	return nil
}

func (c *Container) stop() error {
	state, err := c.pod.storage.fetchState(c.pod.id)
	if err != nil {
		return err
	}

	if state.State != stateRunning {
		return fmt.Errorf("Pod not running, impossible to stop the container")
	}

	state, err = c.pod.storage.fetchState(c.containerPath)
	if err != nil {
		return err
	}

	if state.State != stateRunning {
		return fmt.Errorf("Container not running, impossible to stop")
	}

	err = state.validTransition(stateRunning, stateReady)
	if err != nil {
		return err
	}

	err = c.pod.agent.startAgent()
	if err != nil {
		return err
	}

	err = c.pod.agent.stopContainer(*(c.pod.config), *(c.config))
	if err != nil {
		return err
	}

	err = c.setContainerState(stateReady)
	if err != nil {
		return err
	}

	return nil
}

func (c *Container) enter(cmd Cmd) error {
	state, err := c.pod.storage.fetchState(c.pod.id)
	if err != nil {
		return err
	}

	if state.State != stateRunning {
		return fmt.Errorf("Pod not running, impossible to enter the container")
	}

	state, err = c.pod.storage.fetchState(c.containerPath)
	if err != nil {
		return err
	}

	if state.State != stateRunning {
		return fmt.Errorf("Container not running, impossible to enter")
	}

	err = c.pod.agent.startAgent()
	if err != nil {
		return err
	}

	err = c.pod.agent.exec(c.pod.id, c.id, cmd)
	if err != nil {
		return err
	}

	return nil
}
