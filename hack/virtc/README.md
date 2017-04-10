# virtc

`virtc` is a simple command-line tool that serves to demonstrate typical usage of the virtcontainers API.
This is example software; unlike other projects like runc, runv, or rkt, virtcontainers is not a full container runtime.

## Virtc example

Here we explain how to use the pod and container API from `virtc` command line.

### Prepare your environment

#### Get your kernel

_Fedora_
```
$ sudo -E dnf config-manager --add-repo http://download.opensuse.org/repositories/home:clearlinux:preview:clear-containers-2.0/Fedora_24/home:clearlinux:preview:clear-containers-2.0.repo
$ sudo dnf install linux-container 
```

_Ubuntu_
```
$ sudo sh -c "echo 'deb http://download.opensuse.org/repositories/home:/clearlinux:/preview:/clear-containers-2.0/xUbuntu_16.04/ /' >> /etc/apt/sources.list.d/cc-oci-runtime.list"
$ sudo apt install linux-container
```

#### Get your image

Retrieve a recent Clear Containers image to make sure it contains a recent version of hyperstart agent.
You can dowload the following tested [image](https://download.clearlinux.org/releases/14230/clear/clear-14230-containers.img.xz), or any version more recent.

```
$ wget https://download.clearlinux.org/releases/14230/clear/clear-14230-containers.img.xz
$ unxz clear-14230-containers.img.xz
$ sudo cp clear-14230-containers.img /usr/share/clear-containers/clear-containers.img
```

#### Get virtc

_Download virtcontainers project_
```
$ go get github.com/containers/virtcontainers
```

_Build and setup your environment_
```
$ cd $GOPATH/src/github.com/containers/virtcontainers
$ go build -o virtc hack/virtc/main.go
$ sudo su
# ./utils/virtcontainers-setup.sh 
```

`virtcontainers-setup.sh` setup your environment performing different tasks. Particularly, it creates a __busybox__ bundle, and it creates CNI configuration files needed to run `virtc` with CNI plugins.

### Run virtc

All following commands __MUST__ be run as root. By default, and unless you decide to modify it and rebuild it, `virtc` starts empty pods (no container started).

#### Run a new pod (Create + Start)
```
# ./virtc pod run -agent="hyperstart" -network="CNI" -proxy="ccProxy" -proxy-url="unix:///var/run/clearcontainers/proxy.sock" -pause-path="/tmp/bundles/pause_bundle/rootfs/bin/pause"
```
#### Create a new pod
```
# ./virtc pod run -agent="hyperstart" -network="CNI" -proxy="ccProxy" -proxy-url="unix:///var/run/clearcontainers/proxy.sock" -pause-path="/tmp/bundles/pause_bundle/rootfs/bin/pause"
```
This will generate output similar to the following:
```
Pod 306ecdcf-0a6f-4a06-a03e-86a7b868ffc8 created
```

#### Start an existing pod
```
# ./virtc pod start -id=306ecdcf-0a6f-4a06-a03e-86a7b868ffc8
```
This will generate output similar to the following:
```
Pod 306ecdcf-0a6f-4a06-a03e-86a7b868ffc8 started
```

#### Stop an existing pod
```
# ./virtc pod stop -id=306ecdcf-0a6f-4a06-a03e-86a7b868ffc8
```
This will generate output similar to the following:
```
Pod 306ecdcf-0a6f-4a06-a03e-86a7b868ffc8 stopped
```

#### Get the status of an existing pod and its containers
```
# ./virtc pod status -id=306ecdcf-0a6f-4a06-a03e-86a7b868ffc8
```
This will generate output similar to the following (assuming the pod has been started):
```
POD ID                                  STATE   HYPERVISOR      AGENT
306ecdcf-0a6f-4a06-a03e-86a7b868ffc8    running qemu            hyperstart

CONTAINER ID    STATE
```

#### Delete an existing pod
```
# ./virtc pod delete -id=306ecdcf-0a6f-4a06-a03e-86a7b868ffc8
```
This will generate output similar to the following:
```
Pod 306ecdcf-0a6f-4a06-a03e-86a7b868ffc8 deleted
```

#### List all existing pods
```
# ./virtc pod list
```
This should generate that kind of output
```
POD ID                                  STATE   HYPERVISOR      AGENT
306ecdcf-0a6f-4a06-a03e-86a7b868ffc8    running qemu            hyperstart
92d73f74-4514-4a0d-81df-db1cc4c59100    running qemu            hyperstart
7088148c-049b-4be7-b1be-89b3ae3c551c    ready   qemu            hyperstart
6d57654e-4804-4a91-b72d-b5fe375ed3e1    ready   qemu            hyperstart
```

#### Create a new container
```
# ./virtc container create -id=1 -pod-id=306ecdcf-0a6f-4a06-a03e-86a7b868ffc8 -rootfs="/tmp/bundles/busybox/rootfs" -cmd="/bin/ifconfig"
```
This will generate output similar to the following:
```
Container 1 created
```

#### Start an existing container
```
# ./virtc container start -id=1 -pod-id=306ecdcf-0a6f-4a06-a03e-86a7b868ffc8
```
This will generate output similar to the following:
```
Container 1 started
```

#### Run a new process on an existing container
```
# ./virtc container enter -id=1 -pod-id=306ecdcf-0a6f-4a06-a03e-86a7b868ffc8 -cmd="/bin/ps"
```
This will generate output similar to the following:
```
Container 1 entered
```

#### Stop an existing container
```
# ./virtc container stop -id=1 -pod-id=306ecdcf-0a6f-4a06-a03e-86a7b868ffc8
```
This will generate output similar to the following:
```
Container 1 stopped
```

#### Delete an existing container
```
# ./virtc container delete -id=1 -pod-id=306ecdcf-0a6f-4a06-a03e-86a7b868ffc8
```
This will generate output similar to the following:
```
Container 1 deleted
```

#### Get the status of an existing container
```
# ./virtc container status -id=1 -pod-id=306ecdcf-0a6f-4a06-a03e-86a7b868ffc8
```
This will generate output similar to the following (assuming the container has been started):
```
CONTAINER ID    STATE
1               running
```
