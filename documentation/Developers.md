
Table of Contents
=================

   * [Prerequisites](#prerequisites)
   * [Cloning and Submitting](#cloning-and-submitting)
   * [Building](#building)
   * [Testing](#testing)

# Prerequisites

`virtcontainers` has a few prerequisites for development:

- docker
- CNI
- golang
- gometalinter

A number of these can be installed using the
[virtcontainers-setup.sh](../utils/virtcontainers-setup.sh) script.

# Cloning and Submitting

If you are just builiding `virtcontainers`, then you can simply clone the main repository
from https://github.com/containers/virtcontainers.

If you wish to develop `virtcontainers`, you should fork the project on github under your
user.

**Note:** As `virtcontainers` contains and references its own
[sub packages](https://github.com/containers/virtcontainers/tree/master/pkg),
it will **not** build or pass its tests in your user fork repo (as the
[pkg references](https://github.com/containers/virtcontainers/blob/master/cni.go#L25)
will still reference the main repo, and this results in golang type clashes etc.).

In order to develop and submit PRs for `virtcontainers`, the easiest method is to:

- Create a user fork on github.
- Clone the main repo to your development machine (with `go get`)
- Add your user fork as a 'remote' to the main repo on your development machine.
- Develop and test in a branch in your main repo as per the
[CONTRIBUTING](https://github.com/containers/virtcontainers/blob/master/CONTRIBUTING.md#pull-requests)
guidelines.
- Submit your PR by pushing your branch to *your user fork remote* (and **not** back
to the main repo origin).

# Building

To build `virtcontainers`, at the top level directory run:

```bash
$ make
```

# Testing

Before testing `virtcontainers`, ensure you have met the [prerequisites](#prerequisites).

Before testing you need to install virtcontainers. The following command will install
`virtcontainers` into its own area (`/usr/bin/virtcontainers/bin/` by default).

```
$ sudo -E PATH=$PATH make install
```

You also need to install some extra components required for testing, by running:
```
$ sudo -E PATH=$PATH utils/virtcontainers-setup.sh
```

> Note: this script installs components into **/tmp**. If you reboot your machine,
> those files will *likely be removed*, and you will need to re-run the script again
> before you can successfully run the tests again.

To test `virtcontainers`, at the top level run:

```
$ CI=true make check
```

This will:

- run static code checks on the code base.
- run `go test` unit tests from the code base.
