#!/bin/bash
#
# Copyright (c) 2017 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# This script is used to update the virtcontainers code in the vendor
# directories of the proxy and runtime repositories.

set -e

test_repo="github.com/clearcontainers/tests"
proxy_repo="github.com/clearcontainers/proxy"
runtime_repo="github.com/clearcontainers/runtime"
virtcontainers_repo="github.com/containers/virtcontainers"

# Copy virtcontainers changes to the vendor directory of the repo
function update_repo(){
	repo="$1"
	vc_vendor_dir="${GOPATH}/src/${repo}/vendor/${virtcontainers_repo}"
	rm -rf "${vc_vendor_dir}"
	cp -r "${GOPATH}/src/${virtcontainers_repo}" "${vc_vendor_dir}"
	pushd "${GOPATH}/src/${repo}"
	git clean -fd
	popd
}

update_repo "${proxy_repo}"
update_repo "${runtime_repo}"
pushd "${GOPATH}/src/${test_repo}"
.ci/install_proxy.sh
.ci/install_runtime.sh
popd
