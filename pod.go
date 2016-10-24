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
	"strings"
	"syscall"
	"time"

	"github.com/01org/ciao/ssntp/uuid"
	"github.com/golang/glog"
)

// controlSocket is the pod control socket.
// It is an hypervisor resource, and for example qemu's control
// socket is the QMP one.
const controlSocket = "ctrl.sock"

// monitorSocket is the pod monitoring socket.
// It is an hypervisor resource, and is a qmp socket in the qemu case.
// This is a socket that any monitoring entity will listen to in order
// to understand if the VM is still alive or not.
const monitorSocket = "monitor.sock"

// podResource is an int representing a pod resource type
type podResource int

const (
	// configFileType represents a configuration file type
	configFileType podResource = iota

	// stateFileType represents a state file type
	stateFileType

	// lockFileType represents a lock file type
	lockFileType
)

// configStoragePath is the pod configuration directory.
// It will contain one config.json file for each created pod.
const configStoragePath = "/var/lib/virtcontainers/pods"

// runStoragePath is the pod runtime directory.
// It will contain one state.json and one lock file for each created pod.
const runStoragePath = "/run/virtcontainers/pods"

// configFile is the file name used for every JSON pod configuration.
const configFile = "config.json"

// stateFile is the file name storing a pod state.
const stateFile = "state.json"

// lockFile is the file name locking the usage of a pod.
const lockFile = "lock"

// stateType represents a state type.
type stateType int

const (
	// podStateType represents a pod state type.
	podStateType stateType = iota

	// contStateType represents a container state type.
	contStateType
)

// stateString is a string representing a pod state.
type stateString string

const (
	// podReady represents a pod that's ready to be run
	podReady stateString = "p_ready"

	// podRunning represents a pod that's currently running.
	podRunning = "p_running"

	// podPaused represents a pod that has been paused.
	podPaused = "p_paused"

	// contReady represents a container that's ready to be run
	contReady = "c_ready"

	// contNotReady represents a container that's not ready to be run.
	contNotReady = "c_not_ready"
)

// State is a pod state structure.
type State struct {
	State stateString `json:"state"`
}

// valid checks that the pod state is valid.
func (state *State) valid(stateType stateType) bool {
	var validStates []stateString

	switch stateType {
	case podStateType:
		validStates = []stateString{podReady, podRunning, podPaused}
	case contStateType:
		validStates = []stateString{contReady, contNotReady}
	}

	for _, validState := range validStates {
		if state.State == validState {
			return true
		}
	}

	return false
}

// validTransition returns an error if we want to move to
// an unreachable state.
func (state *State) validTransition(oldState stateString, newState stateString) error {
	if state.State != oldState {
		return fmt.Errorf("Invalid state %s (Expecting %s)", state.State, oldState)
	}

	switch state.State {
	case podReady:
		if newState == podRunning {
			return nil
		}

	case podRunning:
		if newState == podPaused || newState == podReady {
			return nil
		}

	case podPaused:
		if newState == podRunning {
			return nil
		}

	case contNotReady:
		if newState == contReady {
			return nil
		}

	case contReady:
		if newState == contNotReady {
			return nil
		}
	}

	return fmt.Errorf("Can not move from %s to %s",
		state.State, newState)
}

// Volume is a shared volume between the host and the VM,
// defined by its mount tag and its host path.
type Volume struct {
	// MountTag is a label used as a hint to the guest.
	MountTag string

	// HostPath is the host filesystem path for this volume.
	HostPath string
}

// Volumes is a Volume list.
type Volumes []Volume

// Set assigns volume values from string to a Volume.
func (v *Volumes) Set(volStr string) error {
	volSlice := strings.Split(volStr, " ")

	for _, vol := range volSlice {
		volArgs := strings.Split(vol, ":")

		if len(volArgs) != 2 {
			return fmt.Errorf("Wrong string format: %s, expecting only 2 parameters separated with ':'", vol)
		}

		if volArgs[0] == "" || volArgs[1] == "" {
			return fmt.Errorf("Volume parameters cannot be empty")
		}

		volume := Volume{
			MountTag: volArgs[0],
			HostPath: volArgs[1],
		}

		*v = append(*v, volume)
	}

	return nil
}

// String converts a Volume to a string.
func (v *Volumes) String() string {
	var volSlice []string

	for _, volume := range *v {
		volSlice = append(volSlice, fmt.Sprintf("%s:%s", volume.MountTag, volume.HostPath))
	}

	return strings.Join(volSlice, " ")
}

// Socket defines a socket to communicate between
// the host and any process inside the VM.
type Socket struct {
	DeviceID string
	ID       string
	HostPath string
	Name     string
}

// Sockets is a Socket list.
type Sockets []Socket

// Set assigns socket values from string to a Socket.
func (s *Sockets) Set(sockStr string) error {
	sockSlice := strings.Split(sockStr, " ")

	for _, sock := range sockSlice {
		sockArgs := strings.Split(sock, ":")

		if len(sockArgs) != 4 {
			return fmt.Errorf("Wrong string format: %s, expecting only 4 parameters separated with ':'", sock)
		}

		for _, a := range sockArgs {
			if a == "" {
				return fmt.Errorf("Socket parameters cannot be empty")
			}
		}

		socket := Socket{
			DeviceID: sockArgs[0],
			ID:       sockArgs[1],
			HostPath: sockArgs[2],
			Name:     sockArgs[3],
		}

		*s = append(*s, socket)
	}

	return nil
}

// String converts a Socket to a string.
func (s *Sockets) String() string {
	var sockSlice []string

	for _, sock := range *s {
		sockSlice = append(sockSlice, fmt.Sprintf("%s:%s:%s:%s", sock.DeviceID, sock.ID, sock.HostPath, sock.Name))
	}

	return strings.Join(sockSlice, " ")
}

// EnvVar is a key/value structure representing a command
// environment variable.
type EnvVar struct {
	Var   string
	Value string
}

// Cmd represents a command to execute in a running container.
type Cmd struct {
	Args    []string
	Envs    []EnvVar
	WorkDir string

	User  string
	Group string
}

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

// PodConfig is a Pod configuration.
type PodConfig struct {
	ID string

	HypervisorType   HypervisorType
	HypervisorConfig HypervisorConfig

	AgentType   AgentType
	AgentConfig interface{}

	// Rootfs is the pod root file system in the host.
	// This can be left empty if we only have a set of containers
	// workload images and expect the agent to aggregate them into
	// a pod from the guest.
	RootFs string

	// Volumes is a list of shared volumes between the host and the Pod.
	Volumes []Volume

	// Sockets is a list of sockets to allowing the communication
	// between the host and the Pod.
	Sockets []Socket

	// Containers describe the list of containers within a Pod.
	// This list can be empty and populated by adding containers
	// to the Pod a posteriori.
	Containers []ContainerConfig
}

// valid checks that the pod configuration is valid.
func (podConfig *PodConfig) valid() bool {
	if _, err := newAgent(podConfig.AgentType); err != nil {
		glog.Error(err)
		return false
	}

	if _, err := newHypervisor(podConfig.HypervisorType); err != nil {
		podConfig.HypervisorType = QemuHypervisor
	}

	if podConfig.ID == "" {
		podConfig.ID = uuid.Generate().String()
	}

	return true
}

// PodStorage is the virtcontainers pod storage interface.
// The default pod storage implementation is Filesystem.
type podStorage interface {
	storeConfig(config PodConfig) error
	fetchConfig(podID string) (PodConfig, error)
	storeState(podID string, state State, stateType stateType) error
	fetchState(podID string) (State, error)
	delete(podID string) error
}

// Filesystem is a Storage interface implementation.
type filesystem struct {
}

func podDir(podID string, resource podResource) (string, error) {
	var path string

	if podID == "" {
		return "", fmt.Errorf("PodID cannot be empty")
	}

	switch resource {
	case configFileType:
		path = configStoragePath
		break
	case stateFileType, lockFileType:
		path = runStoragePath
		break
	default:
		return "", fmt.Errorf("Invalid pod resource")
	}

	dirPath := filepath.Join(path, podID)

	return dirPath, nil
}

func podFile(podID string, resource podResource) (string, error) {
	var filename string

	if podID == "" {
		return "", fmt.Errorf("PodID cannot be empty")
	}

	dirPath, err := podDir(podID, resource)
	if err != nil {
		return "", err
	}

	switch resource {
	case configFileType:
		filename = configFile
		break
	case stateFileType:
		filename = stateFile
	case lockFileType:
		filename = lockFile
		break
	default:
		return "", fmt.Errorf("Invalid pod resource")
	}

	filePath := filepath.Join(dirPath, filename)

	return filePath, nil
}

// storeConfig is the storage pod configuration storage implementation for filesystem.
func (fs *filesystem) storeConfig(config PodConfig) error {
	if config.valid() == false {
		return fmt.Errorf("Invalid pod configuration")
	}

	podConfigFile, err := podFile(config.ID, configFileType)
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

// fetchConfig is the storage pod configuration retrieval implementation for filesystem.
func (fs *filesystem) fetchConfig(podID string) (PodConfig, error) {
	var config PodConfig

	podConfigFile, err := podFile(podID, configFileType)
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

// storeState is the storage pod state storage implementation for filesystem.
func (fs *filesystem) storeState(podID string, state State, stateType stateType) error {
	if state.valid(stateType) == false {
		return fmt.Errorf("Invalid pod state")
	}

	podStateFile, err := podFile(podID, stateFileType)
	if err != nil {
		return err
	}

	_, err = os.Stat(podStateFile)
	if err == nil {
		os.Remove(podStateFile)
	}

	f, err := os.Create(podStateFile)
	if err != nil {
		return err
	}
	defer f.Close()

	jsonOut, err := json.Marshal(state)
	if err != nil {
		glog.Errorf("Could not marshall pod state: %s\n", err)
		return err
	}
	f.Write(jsonOut)

	return nil
}

// fetchState is the storage pod state retrieval implementation for filesystem.
func (fs *filesystem) fetchState(podID string) (State, error) {
	var state State

	podStateFile, err := podFile(podID, stateFileType)
	if err != nil {
		return state, err
	}

	_, err = os.Stat(podStateFile)
	if err != nil {
		return state, err
	}

	fileData, err := ioutil.ReadFile(podStateFile)
	if err != nil {
		return state, err
	}

	err = json.Unmarshal([]byte(string(fileData)), &state)
	if err != nil {
		return state, err
	}

	return state, nil
}

// delete is the storage pod configuration removal implementation for filesystem.
func (fs *filesystem) delete(podID string) error {
	resources := []podResource{configFileType, stateFileType}

	for _, resource := range resources {
		dir, err := podDir(podID, resource)
		if err != nil {
			return err
		}

		err = os.RemoveAll(dir)
		if err != nil {
			return err
		}
	}

	return nil
}

// Pod is composed of a set of containers and a runtime environment.
// A Pod can be created, deleted, started, stopped, listed, entered, paused and restored.
type Pod struct {
	id string

	hypervisor hypervisor
	agent      agent
	storage    podStorage

	config *PodConfig

	rootFs  string
	volumes []Volume

	containers []ContainerConfig

	runPath    string
	configPath string

	controlSocket string

	state State

	lockFile *os.File
}

// ID returns the pod identifier string.
func (p *Pod) ID() string {
	return p.id
}

// lock locks the current pod to prevent it from being accessed
// by other processes
func (p *Pod) lock() error {
	podlockFile, err := podFile(p.id, lockFileType)
	if err != nil {
		return err
	}

	p.lockFile, err = os.Open(podlockFile)
	if err != nil {
		return err
	}

	err = syscall.Flock(int(p.lockFile.Fd()), syscall.LOCK_EX)
	if err != nil {
		return err
	}

	return nil
}

// unlock unlocks the current pod to allow it being accessed by
// other processes
func (p *Pod) unlock() error {
	err := syscall.Flock(int(p.lockFile.Fd()), syscall.LOCK_UN)
	if err != nil {
		return err
	}

	p.lockFile.Close()

	return nil
}

func (p *Pod) createPodDirs() error {
	err := os.MkdirAll(p.runPath, os.ModeDir)
	if err != nil {
		return err
	}

	err = os.MkdirAll(p.configPath, os.ModeDir)
	if err != nil {
		p.storage.delete(p.id)
		return err
	}

	for _, container := range p.config.Containers {
		path := filepath.Join(p.runPath, container.ID)
		err = os.MkdirAll(path, os.ModeDir)
		if err != nil {
			p.storage.delete(p.id)
			return err
		}
	}

	podlockFile, err := podFile(p.id, lockFileType)
	if err != nil {
		return err
	}

	_, err = os.Stat(podlockFile)
	if err != nil {
		lockFile, err := os.Create(podlockFile)
		if err != nil {
			return err
		}
		lockFile.Close()
	}

	return nil
}

// createPod creates a pod from the sandbox config, the containers list, the hypervisor
// and the agent passed through the Config structure.
// It will create and store the pod structure, and then ask the hypervisor
// to physically create that pod i.e. starts a VM for that pod to eventually
// be started.
func createPod(podConfig PodConfig) (*Pod, error) {
	if podConfig.valid() == false {
		return nil, fmt.Errorf("Invalid pod configuration")
	}

	agent, err := newAgent(podConfig.AgentType)
	if err != nil {
		return nil, err
	}

	hypervisor, err := newHypervisor(podConfig.HypervisorType)
	if err != nil {
		return nil, err
	}

	err = hypervisor.init(podConfig.HypervisorConfig)
	if err != nil {
		return nil, err
	}

	p := &Pod{
		id:         podConfig.ID,
		hypervisor: hypervisor,
		agent:      agent,
		storage:    &filesystem{},
		config:     &podConfig,
		rootFs:     podConfig.RootFs,
		volumes:    podConfig.Volumes,
		containers: podConfig.Containers,
		runPath:    filepath.Join(runStoragePath, podConfig.ID),
		configPath: filepath.Join(configStoragePath, podConfig.ID),
		state:      State{},
	}

	err = p.createPodDirs()
	if err != nil {
		return nil, err
	}

	err = p.lock()
	if err != nil {
		return nil, err
	}
	defer p.unlock()

	err = p.hypervisor.createPod(podConfig)
	if err != nil {
		p.storage.delete(p.id)
		return nil, err
	}

	var agentConfig interface{}

	if podConfig.AgentConfig != nil {
		switch podConfig.AgentConfig.(type) {
		case (map[string]interface{}):
			agentConfig = newAgentConfig(podConfig)
		default:
			agentConfig = podConfig.AgentConfig.(interface{})
		}
	} else {
		agentConfig = nil
	}

	err = p.agent.init(agentConfig, p.hypervisor)
	if err != nil {
		p.storage.delete(p.id)
		return nil, err
	}

	state, err := p.storage.fetchState(p.id)
	if err == nil && state.State != "" {
		return p, nil
	}

	err = p.setPodState(podReady)
	if err != nil {
		p.storage.delete(p.id)
		return nil, err
	}

	err = p.setContainersState(contNotReady)
	if err != nil {
		p.storage.delete(p.id)
		return nil, err
	}

	return p, nil
}

// storePod stores a pod config.
func (p *Pod) storePod() error {
	err := p.lock()
	if err != nil {
		return err
	}
	defer p.unlock()

	fs := filesystem{}
	err = fs.storeConfig(*(p.config))
	if err != nil {
		return err
	}

	return nil
}

// fetchPod fetches a pod config from a pod ID and returns a pod.
func fetchPod(podID string) (*Pod, error) {
	fs := filesystem{}
	config, err := fs.fetchConfig(podID)
	if err != nil {
		return nil, err
	}

	glog.Infof("Info structure:\n%+v\n", config)

	return createPod(config)
}

// delete deletes an already created pod.
// The VM in which the pod is running will be shut down.
func (p *Pod) delete() error {
	err := p.lock()
	if err != nil {
		return err
	}
	defer p.unlock()

	state, err := p.storage.fetchState(p.id)
	if err != nil {
		return err
	}

	if state.State != podReady {
		return fmt.Errorf("Pod not ready, impossible to delete")
	}

	for _, container := range p.config.Containers {
		path := fmt.Sprintf("%s/%s", p.id, container.ID)
		state, err := p.storage.fetchState(path)
		if err != nil {
			return err
		}

		if state.State != contNotReady {
			return fmt.Errorf("Container is ready, impossible to delete")
		}
	}

	err = p.storage.delete(p.id)
	if err != nil {
		return err
	}

	return nil
}

// start starts a pod. The containers that are making the pod
// will be started.
func (p *Pod) start() error {
	err := p.lock()
	if err != nil {
		return err
	}
	defer p.unlock()

	state, err := p.storage.fetchState(p.id)
	if err != nil {
		return err
	}

	err = state.validTransition(podReady, podRunning)
	if err != nil {
		return err
	}

	for _, container := range p.config.Containers {
		path := fmt.Sprintf("%s/%s", p.id, container.ID)
		state, err := p.storage.fetchState(path)
		if err != nil {
			return err
		}

		err = state.validTransition(contNotReady, contReady)
		if err != nil {
			return err
		}
	}

	podStartedCh := make(chan struct{})
	podStoppedCh := make(chan struct{})

	go p.hypervisor.startPod(podStartedCh, podStoppedCh)

	// Wait for the pod started notification
	select {
	case <-podStartedCh:
		break
	case <-time.After(time.Second):
		return fmt.Errorf("Did not receive the pod started notification")
	}

	err = p.agent.start()
	if err != nil {
		p.stop()
		return err
	}

	err = p.agent.startPod(*p.config)
	if err != nil {
		p.stop()
		return err
	}

	interactive := false
	for _, c := range p.config.Containers {
		if c.Interactive != false && c.Console != "" {
			interactive = true
			break
		}
	}

	err = p.setPodState(podRunning)
	if err != nil {
		return err
	}

	err = p.setContainersState(contReady)
	if err != nil {
		return err
	}

	p.unlock()

	if interactive == true {
		select {
		case <-podStoppedCh:
			err = p.setPodState(podReady)
			if err != nil {
				return err
			}

			err = p.setContainersState(contNotReady)
			if err != nil {
				return err
			}

			break
		}
	} else {
		glog.Infof("Created Pod %s\n", p.ID())
	}

	return nil
}

// stop stops a pod. The containers that are making the pod
// will be destroyed.
func (p *Pod) stop() error {
	err := p.lock()
	if err != nil {
		return err
	}
	defer p.unlock()

	state, err := p.storage.fetchState(p.id)
	if err != nil {
		return err
	}

	err = state.validTransition(podRunning, podReady)
	if err != nil {
		return err
	}

	for _, container := range p.config.Containers {
		path := fmt.Sprintf("%s/%s", p.id, container.ID)
		state, err := p.storage.fetchState(path)
		if err != nil {
			return err
		}

		err = state.validTransition(contReady, contNotReady)
		if err != nil {
			return err
		}
	}

	err = p.agent.start()
	if err != nil {
		return err
	}

	err = p.agent.stopPod(*p.config)
	if err != nil {
		return err
	}

	err = p.setPodState(podReady)
	if err != nil {
		return err
	}

	err = p.setContainersState(contNotReady)
	if err != nil {
		return err
	}

	err = p.agent.stop()
	if err != nil {
		return err
	}

	err = p.hypervisor.stopPod()
	if err != nil {
		return err
	}

	return nil
}

// list lists all pod running on the host.
func (p *Pod) list() ([]Pod, error) {
	return nil, nil
}

// enter runs an executable within a pod.
func (p *Pod) enter(args []string) error {
	err := p.lock()
	if err != nil {
		return err
	}
	defer p.unlock()

	return nil
}

func (p *Pod) setPodState(state stateString) error {
	p.state = State{
		State: state,
	}

	err := p.storage.storeState(p.id, p.state, podStateType)
	if err != nil {
		return err
	}

	return nil
}

func (p *Pod) setContainerState(contID string, state stateString) error {
	contState := State{
		State: state,
	}

	path := fmt.Sprintf("%s/%s", p.id, contID)
	err := p.storage.storeState(path, contState, contStateType)
	if err != nil {
		return err
	}

	return nil
}

func (p *Pod) setContainersState(state stateString) error {
	for _, container := range p.config.Containers {
		err := p.setContainerState(container.ID, state)
		if err != nil {
			return err
		}
	}

	return nil
}
