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

type kataProxy struct {
}

// KataProxyConfig is a structure storing information needed for
// the Kata Containers proxy initialization.
type KataProxyConfig struct {
	Path  string
	Debug bool
}

func (k *kataProxy) start(pod Pod) (int, string, error) {
	return 0, "", nil
}

func (k *kataProxy) register(pod Pod) ([]ProxyInfo, string, error) {
	return nil, "", nil
}

func (k *kataProxy) unregister(pod Pod) error {
	return nil
}

func (k *kataProxy) connect(pod Pod, createToken bool) (ProxyInfo, string, error) {
	return ProxyInfo{}, "", nil
}

func (k *kataProxy) disconnect() error {
	return nil
}

func (k *kataProxy) sendCmd(cmd interface{}) (interface{}, error) {
	return nil, nil
}
