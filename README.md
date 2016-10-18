[![Build Status](https://travis-ci.org/sameo/virtcontainers.svg?branch=master)](https://travis-ci.org/sameo/virtcontainers)
[![Go Report Card](https://goreportcard.com/badge/github.com/sameo/virtcontainers)](https://goreportcard.com/report/github.com/sameo/virtcontainers)

# VirtContainers

VirtContainers is a Go package for building hardware virtualized container runtimes.

## Scope

VirtContainers is not a container runtime implementation, but aims at factorizing
hardware virtualization code in order to build VM based container runtimes.

The few existing VM based container runtimes (Clear Containers, RunV, Rkt
kvm stage 1) all share the same hardware virtualization semantics but use different
code bases to implement them. VirtContainers goal is to factorize this code into
a common Go library.

Ideally VM based container runtime implementations would become translation layers
from the runtime specification they implement to the VirtContainers API.

## Out of scope

Implementing yet another container runtime is out of VirtContainers scope. Any tools
or executables provided with VirtContainers are only provided for demonstration or
testing purposes.

## Design

### Goals

VirtContainers is a container specification agnostic Go package and thus tries to
abstract the various container runtime specifications (OCI, AppC and CRI) and present
that as its high level API.

### Pods

The VirtContainers execution unit is a Pod, i.e. VirtContainers callers start pods
where containers will be running.

Virtcontainers creates a pod by starting a virtual machine and setting the pod up within
that environment. Starting a pod means launching all containers with the VM pod runtime
environment.

### Hypervisors

The virtcontainers package relies on hypervisors to start and stop virtual machine where
pods will be running. An hypervisor is defined by an Hypervisor interface implementation,
and the default implementation is the QEMU one.

### Agents

During the lifecycle of a container, the runtime running on the host needs to interact with
the virtual machine guest OS in order to start new commands to be executed as part of a given
container workload, set new networking routes or interfaces, fetch a container standard or
error output, and so on.
There are many existing and potential solutions to resolve that problem and virtcontainers abstract
this through the Agent interface.

## API

The high level VirtContainers API is the following one:

### Pod API

* `CreatePod(podConfig PodConfig)` creates a Pod.
The Pod is prepared and will run into a virtual machine. It is not started, i.e. the VM is not running after `CreatePod()` is called.

* `DeletePod(podID string)` deletes a Pod.
The function will fail if the Pod is running. In that case `StopPod()` needs to be called first.

* `StartPod(podID string)` starts an already created Pod.

* `StopPod(podID string)` stops an already running Pod.

* `ListPod()` lists all running Pods on the host.

* `EnterPod(cmd Cmd)` enters a Pod root filesystem and runs a given command.

* `PodStatus(podID string)` returns a detailed Pod status.

### Container API

* `CreateContainer(podID string, container ContainerConfig)` creates a Container on a given Pod.

* `DeleteContainer(containerID string)` deletes a Container from a Pod. If the container is running it needs to be stopped first.

* `StartContainer(containerID string)` starts an already created container.

* `StopContainer(containerID string)` stops an already running container.

* `EnterContainer(containerID string, cmd Cmd)` enters an already running container and runs a given command.

* `ContainerStatus(containerID string)` returns a detailed container status.
