/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package e2e

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/openshift/oauth-proxy/test/e2e/framework"
)

var _ = framework.OAuthProxyDescribe("oauth-proxy", func() {
	f := framework.NewDefaultFramework("oauth-proxy")

	proxyName := "proxy"

	BeforeEach(func() {
		By("Creating an oauth-proxy pod")
		pod, err := f.KubeClientSet.CoreV1().Pods(f.Namespace.Name).Create(NewOAuthProxyPod(proxyName))
		Expect(err).NotTo(HaveOccurred())
		By("Waiting for pod to be running")
		err = framework.WaitForPodRunningInNamespace(f.KubeClientSet, pod)
		Expect(err).NotTo(HaveOccurred())
		By("Creating a proxy service")
		_, err = f.KubeClientSet.CoreV1().Services(f.Namespace.Name).Create(NewOAuthProxyService(proxyName))
		Expect(err).NotTo(HaveOccurred())
		By("Waiting for service endpoint")
		err = framework.WaitForEndpoint(f.KubeClientSet, f.Namespace.Name, proxyName)
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		By("Deleting the oauth-proxy pod")
		err := f.KubeClientSet.CoreV1().Pods(f.Namespace.Name).Delete(proxyName, nil)
		Expect(err).NotTo(HaveOccurred())
		By("Deleting the oauth-proxy service")
		err = f.KubeClientSet.CoreV1().Services(f.Namespace.Name).Delete(proxyName, nil)
		Expect(err).NotTo(HaveOccurred())
	})

	It("Run walkthrough-example ", func() {

	})

})
