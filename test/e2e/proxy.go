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
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"golang.org/x/net/html"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"text/template"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/openshift/oauth-proxy/test/e2e/framework"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	corev1 "k8s.io/client-go/pkg/api/v1"
)

type RouteTemplate struct {
	AppLabel   string
	NameLabel  string
	TargetPort int32
	ToName     string
	Namespace  string
}

var routeYaml = `apiVersion: v1
kind: Route
metadata:
  labels:
    app: {{.AppLabel}}
  name: {{.NameLabel}}
  namespace: {{.Namespace}}
spec:
  port:
    targetPort: {{.TargetPort}}
  to:
    kind: Service
    name: {{.ToName}}
    weight: 100
  wildcardPolicy: None
  tls:
    termination: passthrough
`

func createParsedCertificate(template, parent *x509.Certificate, sigKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Self-signed
	if sigKey == nil {
		sigKey = key
	}

	raw, err := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), sigKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}

func encodeCert(certificate *x509.Certificate) ([]byte, error) {
	var certBytes bytes.Buffer
	wb := bufio.NewWriter(&certBytes)
	err := pem.Encode(wb, &pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	if err != nil {
		return nil, err
	}
	wb.Flush()
	return certBytes.Bytes(), nil
}

func encodeKey(key *rsa.PrivateKey) ([]byte, error) {
	var keyBytes bytes.Buffer
	wb := bufio.NewWriter(&keyBytes)
	err := pem.Encode(wb, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err != nil {
		return nil, err
	}
	wb.Flush()
	return keyBytes.Bytes(), nil
}

func createCAandCertSet(host string) ([]byte, []byte, []byte, error) {
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour * 24 * 365)
	casub := pkix.Name{
		CommonName: "oauth-proxy-test-ca",
	}
	serverSubj := pkix.Name{
		CommonName: host,
	}

	caTemplate := &x509.Certificate{
		SignatureAlgorithm:    x509.SHA256WithRSA,
		SerialNumber:          big.NewInt(1),
		Issuer:                casub,
		Subject:               casub,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:       true,
		MaxPathLen: 10,
	}

	caCert, caKey, err := createParsedCertificate(caTemplate, caTemplate, nil)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error creating certificate %s, %v", caTemplate.Subject.CommonName, err)
	}

	serverTemplate := &x509.Certificate{
		SignatureAlgorithm:    x509.SHA256WithRSA,
		SerialNumber:          big.NewInt(2),
		Issuer:                casub,
		Subject:               serverSubj,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:     false,
		DNSNames: []string{host},
	}

	serverCert, serverKey, err := createParsedCertificate(serverTemplate, caCert, caKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error creating certificate %s, %v", caTemplate.Subject.CommonName, err)
	}

	pemCA, err := encodeCert(caCert)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error encoding CA cert %v", err)
	}
	pemServerCert, err := encodeCert(serverCert)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error encoding server cert %v", err)
	}
	pemServerKey, err := encodeKey(serverKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error encoding server key %v", err)
	}

	return pemCA, pemServerCert, pemServerKey, nil
}

var _ = framework.OAuthProxyDescribe("oauth-proxy", func() {
	appName := "proxy"
	routeName := "proxy-route"
	routePort := int32(8443)
	testName := "basic"
	servicePort := int32(443)
	serviceTargetPort := 8443
	oauthProxyArgs := []string{
		"--https-address=:8443",
		"--provider=openshift",
		"--openshift-service-account=proxy",
		"--upstream=http://localhost:8080",
		"--tls-cert=/etc/tls/private/tls.crt",
		"--tls-key=/etc/tls/private/tls.key",
		"--tls-client-ca=/etc/tls/private/ca.crt",
		"--cookie-secret=SECRET",
	}

	image := os.Getenv("DOCKER_IMG")
	if image == "" {
		image = "docker.io/openshift/oauth-proxy:v1.0.0"
	}

	f := framework.NewDefaultFramework("oauth-proxy")

	It(fmt.Sprintf("running test: %s, namespace: %s", testName, f.Namespace.Name), func() {

		By(fmt.Sprintf("creating oauth-proxy service account with annotation for route '%s'", routeName))
		_, err := f.KubeClientSet.CoreV1().ServiceAccounts(f.Namespace.Name).Create(newOAuthProxySA(routeName))
		Expect(err).NotTo(HaveOccurred())

		By(fmt.Sprintf("creating route '%s' with port %v to oauth-proxy", routeName, routePort))
		err = newOAuthProxyRoute(appName, routeName, appName, f.Namespace.Name, routePort)
		Expect(err).NotTo(HaveOccurred())

		// Find the exposed route hostname that we will be doing client actions against
		proxyRouteHost, err := getRouteHost(routeName, f.Namespace.Name)
		Expect(err).NotTo(HaveOccurred())

		By(fmt.Sprintf("creating certificates for host '%s'", proxyRouteHost))
		caPem, serviceCert, serviceKey, err := createCAandCertSet(proxyRouteHost)
		Expect(err).NotTo(HaveOccurred())

		By(fmt.Sprintf("creating oauth-proxy service with ports '%v:%v'", servicePort, serviceTargetPort))
		_, err = f.KubeClientSet.CoreV1().Services(f.Namespace.Name).Create(newOAuthProxyService(appName,
			appName,
			servicePort,
			serviceTargetPort),
		)
		Expect(err).NotTo(HaveOccurred())

		// configMap provides oauth-proxy with the certificates we created above
		By("creating oauth-proxy pod configMap")
		_, err = f.KubeClientSet.CoreV1().ConfigMaps(f.Namespace.Name).Create(newOAuthProxyConfigMap(f.Namespace.Name,
			caPem,
			serviceCert,
			serviceKey),
		)
		Expect(err).NotTo(HaveOccurred())

		By(fmt.Sprintf("creating oauth-proxy pod with image '%s' and args '%v'", image, oauthProxyArgs))
		oauthProxyPod, err := f.KubeClientSet.CoreV1().Pods(f.Namespace.Name).Create(newOAuthProxyPod(image, oauthProxyArgs))
		Expect(err).NotTo(HaveOccurred())

		By("waiting for oauth-proxy pod to be running")
		err = framework.WaitForPodRunningInNamespace(f.KubeClientSet, oauthProxyPod)
		Expect(err).NotTo(HaveOccurred())

		// Find the service CA for the client trust store
		secrets, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).List(metav1.ListOptions{})
		Expect(err).NotTo(HaveOccurred())
		var openshiftPemCA []byte
		for _, s := range secrets.Items {
			cert, ok := s.Data["ca.crt"]
			if !ok {
				continue
			}
			openshiftPemCA = cert
			break
		}
		Expect(openshiftPemCA).ShouldNot(BeNil())

		By("stepping through oauth-proxy auth flow")
		err = confirmOAuthFlow(proxyRouteHost, [][]byte{caPem, openshiftPemCA})
		Expect(err).NotTo(HaveOccurred())

		// clean up
		/*
			By("Deleting the oauth-proxy oauthProxyPod")
			err = f.KubeClientSet.CoreV1().Pods(f.Namespace.Name).Delete(appName, nil)
			Expect(err).NotTo(HaveOccurred())
			By("Deleting the oauth-proxy service")
			err = f.KubeClientSet.CoreV1().Services(f.Namespace.Name).Delete(appName, nil)
			Expect(err).NotTo(HaveOccurred())
		*/
	})
})

func getResponse(host string, client *http.Client) (*http.Response, error) {
	req, err := http.NewRequest("GET", host, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func confirmOAuthFlow(host string, cas [][]byte) error {
	// Set up the client cert store
	pool := x509.NewCertPool()
	for i := range cas {
		if !pool.AppendCertsFromPEM(cas[i]) {
			return fmt.Errorf("error loading CA for client config")
		}
	}

	jar, _ := cookiejar.New(nil)
	tr := &http.Transport{
		MaxIdleConns:    10,
		IdleConnTimeout: 30 * time.Second,
		TLSClientConfig: &tls.Config{
			RootCAs: pool,
		},
	}

	client := &http.Client{Transport: tr, Jar: jar}

	// Go straight to start, redirecting to OpenShift login
	startUrl := "https://" + host + "/oauth/start"
	resp, err := getResponse(startUrl, client)
	if err != nil {
		return err
	}

	// OpenShift login
	loginResp, err := submitOAuthForm(client, resp)
	if err != nil {
		return err
	}

	// authorization grant form
	accessResp, err := submitOAuthForm(client, loginResp)
	if err != nil {
		return err
	}

	accessRespBody, err := ioutil.ReadAll(accessResp.Body)
	if err != nil {
		return nil
	}

	fmt.Printf("response body: %s\n", string(accessRespBody))
	if string(accessRespBody) != "Hello OpenShift!\n" {
		return fmt.Errorf("did not reach backend site")
	}

	return nil
}

func visit(n *html.Node, visitor func(*html.Node)) {
	visitor(n)
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		visit(c, visitor)
	}
}

func getElementsByTagName(root *html.Node, tagName string) []*html.Node {
	elements := []*html.Node{}
	visit(root, func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == tagName {
			elements = append(elements, n)
		}
	})
	return elements
}

func getAttr(element *html.Node, attrName string) (string, bool) {
	for _, attr := range element.Attr {
		if attr.Key == attrName {
			return attr.Val, true
		}
	}
	return "", false
}

// newRequestFromForm builds a request that simulates submitting the given form.
func newRequestFromForm(form *html.Node, currentURL *url.URL) (*http.Request, error) {
	var (
		reqMethod string
		reqURL    *url.URL
		reqBody   io.Reader
		reqHeader = http.Header{}
		err       error
	)

	// Method defaults to GET if empty
	if method, _ := getAttr(form, "method"); len(method) > 0 {
		reqMethod = strings.ToUpper(method)
	} else {
		reqMethod = "GET"
	}

	// URL defaults to current URL if empty
	action, _ := getAttr(form, "action")
	reqURL, err = currentURL.Parse(action)
	if err != nil {
		return nil, err
	}

	formData := url.Values{}
	if reqMethod == "GET" {
		// Start with any existing query params when we're submitting via GET
		formData = reqURL.Query()
	}
	addedSubmit := false
	for _, input := range getElementsByTagName(form, "input") {
		if name, ok := getAttr(input, "name"); ok {
			if value, ok := getAttr(input, "value"); ok {
				inputType, _ := getAttr(input, "type")

				switch inputType {
				case "text":
					if name == "username" {
						formData.Add(name, "developer")
					}
				case "password":
					if name == "password" {
						formData.Add(name, "foo")
					}
				case "submit":
					// If this is a submit input, only add the value of the first one.
					// We're simulating submitting the form.
					if !addedSubmit {
						formData.Add(name, value)
						addedSubmit = true
					}
				case "radio", "checkbox":
					if _, checked := getAttr(input, "checked"); checked {
						formData.Add(name, value)
					}
				default:
					formData.Add(name, value)
				}
			}
		}
	}

	switch reqMethod {
	case "GET":
		reqURL.RawQuery = formData.Encode()
	case "POST":
		reqHeader.Set("Content-Type", "application/x-www-form-urlencoded")
		reqBody = strings.NewReader(formData.Encode())
	default:
		return nil, fmt.Errorf("unknown method: %s", reqMethod)
	}

	req, err := http.NewRequest(reqMethod, reqURL.String(), reqBody)
	if err != nil {
		return nil, err
	}

	req.Header = reqHeader
	return req, nil
}

func submitOAuthForm(client *http.Client, response *http.Response) (*http.Response, error) {
	body, err := html.Parse(response.Body)
	if err != nil {
		return nil, err
	}

	forms := getElementsByTagName(body, "form")
	if len(forms) != 1 {
		return nil, fmt.Errorf("expected OpenShift form")
	}

	formReq, err := newRequestFromForm(forms[0], response.Request.URL)
	if err != nil {
		return nil, err
	}

	postResp, err := client.Do(formReq)
	if err != nil {
		return nil, err
	}

	return postResp, nil
}

// execCmd executes a command and returns the stdout + error, if any
func execCmd(cmd string) (string, error) {
	parts := strings.Fields(cmd)
	head := parts[0]
	parts = parts[1:]

	out, err := exec.Command(head, parts...).CombinedOutput()
	if err != nil {
		fmt.Printf("Command '%s' failed with: %s\n", cmd, err)
		fmt.Printf("Output: %s\n", out)
		return "", err
	}
	return string(out), nil
}

func getRouteHost(routeName, namespace string) (string, error) {
	out, err := execCmd(fmt.Sprintf("oc get route/%s -o jsonpath='{.spec.host}' -n %s", routeName, namespace))
	if err != nil {
		return "", err
	}
	// strip single quotes
	return out[1 : len(out)-1], nil
}

func newOAuthProxyService(serviceName, appLabel string, port int32, targetPort int) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: serviceName,
			Labels: map[string]string{
				"app": appLabel,
			},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app": appLabel,
			},
			Ports: []corev1.ServicePort{
				{
					Protocol:   corev1.ProtocolTCP,
					Port:       port,
					TargetPort: intstr.FromInt(targetPort),
				},
			},
		},
	}
}

func newOAuthProxyRoute(app, name, toname, namespace string, port int32) error {
	tmpl, err := template.New("route").Parse(routeYaml)
	if err != nil {
		return err
	}

	routeYamlFile, err := ioutil.TempFile(os.TempDir(), "proxy-test-route")
	if err != nil {
		return err
	}
	defer routeYamlFile.Close()

	// execute template
	writer := bufio.NewWriter(routeYamlFile)
	err = tmpl.Execute(writer, RouteTemplate{
		AppLabel:   app,
		NameLabel:  name,
		TargetPort: port,
		ToName:     toname,
		Namespace:  namespace,
	})

	if err != nil {
		return err
	}
	writer.Flush()

	// create route
	out, err := execCmd(fmt.Sprintf("oc create -f %s", routeYamlFile.Name()))
	if err != nil {
		fmt.Printf(out)
		return err
	}
	return nil
}

// Create SA with an annotation for route routeName
func newOAuthProxySA(routeName string) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name: "proxy",
			Annotations: map[string]string{
				"serviceaccounts.openshift.io/oauth-redirectreference.primary": `{"kind":"OAuthRedirectReference","apiVersion":"v1","reference":{"kind":"Route","name":"` + routeName + `"}}`,
			},
		},
	}
}

func newOAuthProxyConfigMap(namespace string, pemCA, pemServerCert, pemServerKey []byte) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ConfigMap",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "proxy-certs",
			Namespace: namespace,
		},
		Data: map[string]string{
			"ca.crt":  "|\n" + string(pemCA),
			"tls.crt": "|\n" + string(pemServerCert),
			"tls.key": "|\n" + string(pemServerKey),
		},
	}
}

func newOAuthProxyPod(proxyImage string, proxyArgs []string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "proxy",
			Labels: map[string]string{
				"app": "proxy",
			},
		},
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{
				{
					Name: "proxy-cert-volume",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: "proxy-certs"},
						},
					},
				},
			},
			ServiceAccountName: "proxy",
			Containers: []corev1.Container{
				{
					Image:           proxyImage,
					ImagePullPolicy: corev1.PullIfNotPresent,
					Name:            "oauth-proxy",
					Args:            proxyArgs,
					Ports: []corev1.ContainerPort{
						{
							ContainerPort: 8443,
						},
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							MountPath: "/etc/tls/private",
							Name:      "proxy-cert-volume",
						},
					},
				},
				{
					Image: "openshift/hello-openshift",
					Name:  "hello-openshift",
					Ports: []corev1.ContainerPort{
						{
							ContainerPort: 8080,
						},
					},
				},
			},
		},
	}
}
