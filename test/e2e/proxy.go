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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"golang.org/x/net/html"
	"io"
	"io/ioutil"
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

var (
	tlsCA = `-----BEGIN CERTIFICATE-----
MIIDQDCCAiigAwIBAgIBATANBgkqhkiG9w0BAQsFADAeMRwwGgYDVQQDDBNvYXV0
aC1wcm94eS10ZXN0LWNhMB4XDTE3MTEwOTIyMDkxOFoXDTI4MTAyMjIyMDkxOFow
HjEcMBoGA1UEAwwTb2F1dGgtcHJveHktdGVzdC1jYTCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBAK3CdTH+6N6Ly+jvCnURfiZt19T7iEMJ14CilV6ojLfj
x/In1SVDWXzqqqAIlqRw8IMW3eXhjtrvtY4yDItnC9oX03HCLGXRpo+/eu5A73Wh
zEOh5m5+rxxNdFd3ghOX74FzI3dEwimq5J6ZSIHmV8L+PA1EkEa3d2NEY3cG3nAv
XKL18dGxqyKrUJBA56e/21e0qnsAqgpHejj8MAHk3gvs8H2nTGa+O4+e50wdzGR7
pM12onXNRUn06pKrSBBioe9eCc9O6B/8hekHn1an4HItK6ndAMU8GSo579+QiZZU
e8dhGoe3AIilLll8/hGnLLXzmuO04eTt3qgxFe/h1WMCAwEAAaOBiDCBhTAdBgNV
HQ4EFgQUwI/qdzSddmyeAAFW/rYJeT/aLigwRgYDVR0jBD8wPYAUwI/qdzSddmye
AAFW/rYJeT/aLiihIqQgMB4xHDAaBgNVBAMME29hdXRoLXByb3h5LXRlc3QtY2GC
AQEwCwYDVR0PBAQDAgKkMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQAD
ggEBAFmKFcOiu15rwxUyzuLITRCgRREld/ACuhGL8N0ruHp5dibUIOJ2mAZ/wOx+
Q52n7rbvR4vP4jTXq8MHZXirhKZBtH+0sH4ksIBTgtzTU3P90CN/Hawiq4viqg3h
CYx3NB6ye6qY5ZrWNB0ICBTVV0QPkZXIwjh9eiGAZOxDDLeFEC6r7dsUwshO5vx0
OzrF0xS/Iziooys+K3OL5TJTiroQUYKdFvgZt9deCUINWecbnFJKScq9+Vc6Gxae
eyeNAHZL860UhSMWN2jkrRWf4YQrZqSCu4FFhrdylcku6YZEcxxAYH66dSbBQN2T
vUWDVdsFR0p8OfrW0DirEQWWvMU=
-----END CERTIFICATE-----`
	tlsPrivKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEArcJ1Mf7o3ovL6O8KdRF+Jm3X1PuIQwnXgKKVXqiMt+PH8ifV
JUNZfOqqoAiWpHDwgxbd5eGO2u+1jjIMi2cL2hfTccIsZdGmj7967kDvdaHMQ6Hm
bn6vHE10V3eCE5fvgXMjd0TCKarknplIgeZXwv48DUSQRrd3Y0RjdwbecC9covXx
0bGrIqtQkEDnp7/bV7SqewCqCkd6OPwwAeTeC+zwfadMZr47j57nTB3MZHukzXai
dc1FSfTqkqtIEGKh714Jz07oH/yF6QefVqfgci0rqd0AxTwZKjnv35CJllR7x2Ea
h7cAiKUuWXz+EacstfOa47Th5O3eqDEV7+HVYwIDAQABAoIBAQCiFJ3VQP5feO+A
HFoY0XRmzFdjqC12uxt2NjI21epNLgA4dcdwtt4mk48NMHW0dlUjMpVR9ZCX0Ln+
Jdllv31ito7ZslJPt7wyol49F/1GMOKkw8R6lVkqgWVgoW2IcVVL3ubaPh0PWQVg
m4LzCLYcgaHqjmY2ULTgt85AHPwoj7pdNyok/+TE7rahAGFHlWVdno5xdQC1iiTh
BB+6O2pFOxgGAja55Js412z+0gEsinEAwQekOSLnVtwFXiDwGUZrJ1N8xXtejU13
QbzKVgji9w+DnI/onMJUn27DF27iyhlLQqslbLF0Kk4blMgVEXodCpU0EGzlPagi
FDTh/28hAoGBAOXt0x1PQR4cDNLMgaHUP4ZAivNPzAa2ZtK1BkKdjnMif3Aayli+
ugv8FD2nVopI3bBuBDwcHoM4LUXrqYrxBkRRJizFXYb/KBzK3K+mGgXcbc0yikF5
I0e6jbAUyTw6Ia1PMk18TEvJx+f9BJX9d/J9g+hSodx6H4+/nGIpbrRHAoGBAMF2
Mo/H7fSbvEaW18T2sy7vyFO4XZWQkeZEUh6lTNWLLtUFxTrUTs4mCBm6wmaL7oB+
y6mMc1jj5HlEa5fXzz9ufQQIrrpgIKjRdACbhS4mUpAwA/RKlirlRY245XqCtD0E
moOkldf385gL0hdEGf205AEqlkq5cH+4knZGPTAFAoGAedpsQ+A4tmhPM3hGSylc
8R1Lhl8H1ZbdL1XYl31AfSwPNa49BoMtviQ95d7FMkwjkNj9TY3pbclb1O5rz8Kk
e5g2DwwZ4O1gqMGp6zywFeMYHeNm+gPk+qKXbHXXoB9+sYaDNiVlmdS6KOwifgry
goSaX4lLVrkx+NCnZC5pCQkCgYBwIfRYhkeUOhg8yf2yelONZwo0DG6h3DPUxdDb
VnBcbdntOvUAjkJHFqAnWaqICZ9p9xRQ58mLwjuRVmkOj9XeLEpl5ipweHs1noGg
QIRHJYtBa7M/C2RS5KUV6g+InO2fWGW+28zGaz9T57YUKjLubMSjMG4ATc+5F+A8
kaWxiQKBgQDTxHP2exwygCpm2M6TTJelhtOAQ1r2+5MdC10U1qQXYJBD5bDnX1YQ
crYu5d9mzNI9p/e+k/BlFZ3KRp/tgarVaVMEqWtPsOxTnna0rUJLFaQHb3lqAlC+
wSmE9Sm3TQpTq5uL6Kz4U9OOD2V4kelYnsaHH2A0yE5v5SiSFSkeOA==
-----END RSA PRIVATE KEY-----`
	tlsCert = `-----BEGIN CERTIFICATE-----
MIIDZDCCAkygAwIBAgIBAjANBgkqhkiG9w0BAQsFADAeMRwwGgYDVQQDDBNvYXV0
aC1wcm94eS10ZXN0LWNhMB4XDTE3MTEwOTIyMDkxOFoXDTI4MTAyMjIyMDkxOFow
FDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEArcJ1Mf7o3ovL6O8KdRF+Jm3X1PuIQwnXgKKVXqiMt+PH8ifVJUNZfOqq
oAiWpHDwgxbd5eGO2u+1jjIMi2cL2hfTccIsZdGmj7967kDvdaHMQ6Hmbn6vHE10
V3eCE5fvgXMjd0TCKarknplIgeZXwv48DUSQRrd3Y0RjdwbecC9covXx0bGrIqtQ
kEDnp7/bV7SqewCqCkd6OPwwAeTeC+zwfadMZr47j57nTB3MZHukzXaidc1FSfTq
kqtIEGKh714Jz07oH/yF6QefVqfgci0rqd0AxTwZKjnv35CJllR7x2Eah7cAiKUu
WXz+EacstfOa47Th5O3eqDEV7+HVYwIDAQABo4G2MIGzMB0GA1UdDgQWBBTAj+p3
NJ12bJ4AAVb+tgl5P9ouKDBGBgNVHSMEPzA9gBTAj+p3NJ12bJ4AAVb+tgl5P9ou
KKEipCAwHjEcMBoGA1UEAwwTb2F1dGgtcHJveHktdGVzdC1jYYIBATALBgNVHQ8E
BAMCBaAwDAYDVR0TAQH/BAIwADAaBgNVHREEEzARgglsb2NhbGhvc3SHBH8AAAEw
EwYDVR0lBAwwCgYIKwYBBQUHAwEwDQYJKoZIhvcNAQELBQADggEBAIMbrhhFgFWo
01KlDpzm11Sy9e68ViaCuYn5eUYmL8NboFMVdxpaztRl38VUG2mj/c6++2q0yKJA
ZhcpGU1O/ifN06E/Cq3wggz0ybIeSwOIH1nR+5cJ4P5c+JzgG27IO6fF+7v5XXJa
JdfRq3l55voThAyD/sOuvvb0wJc3/lDgrX661DJsi5qgplbJZOOs6J/KSYWb06Qc
pC6hkLXhkVaGRxQ/kRPEU/QVfEOfetNCOJ4L6BIz4sOyxNvW7GX/zwKtOu52Duq9
eaSm+IzbFos9DKNw3xaAAvUAfXqe8fPjllfRGJplLTCk7SL/SaFb1gDxXxtrZELe
ZJ/0sHCv5PI=
-----END CERTIFICATE-----`
)

var _ = framework.OAuthProxyDescribe("oauth-proxy", func() {

	appName := "proxy"
	image := os.Getenv("DOCKER_IMG")
	if image == "" {
		image = "docker.io/openshift/oauth-proxy:v1.0.0"
	}

	f := framework.NewDefaultFramework("oauth-proxy")

	It("Run walkthrough-example ", func() {
		By("Creating an oauth-proxy SA")
		_, err := f.KubeClientSet.CoreV1().ServiceAccounts(f.Namespace.Name).Create(NewOAuthProxySA())
		Expect(err).NotTo(HaveOccurred())

		By("Creating an oauth-proxy route")
		err = NewOAuthProxyRoute(appName, "proxy-route", appName, f.Namespace.Name, 8443)
		Expect(err).NotTo(HaveOccurred())

		By("Creating a proxy service")
		_, err = f.KubeClientSet.CoreV1().Services(f.Namespace.Name).Create(NewOAuthProxyService(appName, appName, 443, 8443))
		Expect(err).NotTo(HaveOccurred())

		By("Creating the proxy TLS configmap")
		_, err = f.KubeClientSet.CoreV1().ConfigMaps(f.Namespace.Name).Create(NewOAuthProxyConfigMap(f.Namespace.Name))
		Expect(err).NotTo(HaveOccurred())

		By("Creating an oauth-proxy pod")
		pod, err := f.KubeClientSet.CoreV1().Pods(f.Namespace.Name).Create(NewOAuthProxyPod(image, []string{
			"--https-address=:8443",
			"--provider=openshift",
			"--openshift-service-account=proxy",
			"--upstream=http://localhost:8080",
			"--tls-cert=/etc/tls/private/tls.crt",
			"--tls-key=/etc/tls/private/tls.key",
			"--cookie-secret=SECRET",
		}))
		Expect(err).NotTo(HaveOccurred())

		By("Waiting for pod to be running")
		err = framework.WaitForPodRunningInNamespace(f.KubeClientSet, pod)
		Expect(err).NotTo(HaveOccurred())

		host, err := getRouteHost("proxy-route", f.Namespace.Name)
		Expect(err).NotTo(HaveOccurred())

		// xxx
		fmt.Println(host)

		// Find the service CA for the client trust store
		secrets, err := f.KubeClientSet.CoreV1().Secrets(f.Namespace.Name).List(metav1.ListOptions{})
		Expect(err).NotTo(HaveOccurred())
		var caPem []byte
		for _, s := range secrets.Items {
			cert, ok := s.Data["service-ca.crt"]
			if !ok {
				continue
			}
			caPem = cert
			break
		}
		Expect(caPem).ShouldNot(BeNil())
		fmt.Println(string(caPem))
		err = confirmOAuthFlow(host, caPem)
		Expect(err).NotTo(HaveOccurred())

		// clean up
		/*
			By("Deleting the oauth-proxy pod")
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

func confirmOAuthFlow(host string, ca []byte) error {
	// Set up the client cert store
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return fmt.Errorf("Error loading CA for client config")
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

	startUrl := "https://" + host[1:len(host)-1] + "/oauth/start"
	resp, err := getResponse(startUrl, client)
	if err != nil {
		return err
	}

	loginResp, err := submitOAuthForm(client, resp)
	if err != nil {
		return err
	}

	accessResp, err := submitOAuthForm(client, loginResp)
	if err != nil {
		return err
	}

	accessRespBody, err := ioutil.ReadAll(accessResp.Body)
	if err != nil {
		return nil
	}
	fmt.Println(string(accessRespBody))
	if string(accessRespBody) != "Hello OpenShift!\n" {
		return fmt.Errorf("did not reach backend site")
	}

	return nil
}

func submitOAuthForm(client *http.Client, response *http.Response) (*http.Response, error) {
	body, err := html.Parse(response.Body)
	if err != nil {
		return nil, err
	}

	forms := GetElementsByTagName(body, "form")
	if len(forms) != 1 {
		return nil, fmt.Errorf("expected OpenShift form")
	}

	formReq, err := NewRequestFromForm(forms[0], response.Request.URL)
	if err != nil {
		return nil, err
	}

	postResp, err := client.Do(formReq)
	if err != nil {
		return nil, err
	}

	return postResp, nil
}

// ExecCmd executes a command and returns the stdout + error, if any
func ExecCmd(cmd string) (string, error) {
	fmt.Println("command: " + cmd)

	parts := strings.Fields(cmd)
	head := parts[0]
	parts = parts[1:]

	out, err := exec.Command(head, parts...).CombinedOutput()
	if err != nil {
		fmt.Printf("Command failed with: %s\n", err)
		fmt.Printf("Output: %s\n", out)
		return "", err
	}
	return string(out), nil
}

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

func getRouteHost(routeName, namespace string) (string, error) {
	out, err := ExecCmd(fmt.Sprintf("oc get route/%s -o jsonpath='{.spec.host}' -n %s", routeName, namespace))
	if err != nil {
		return "", err
	}
	return out, nil
}
func NewOAuthProxyRoute(app, name, toname, namespace string, port int32) error {
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
	out, err := ExecCmd(fmt.Sprintf("oc create -f %s", routeYamlFile.Name()))
	if err != nil {
		fmt.Printf(out)
		return err
	}
	return nil
}

func NewOAuthProxySA() *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name: "proxy",
			Annotations: map[string]string{
				"serviceaccounts.openshift.io/oauth-redirectreference.primary": `{"kind":"OAuthRedirectReference","apiVersion":"v1","reference":{"kind":"Route","name":"proxy-route"}}`,
			},
		},
	}
}

func NewOAuthProxyConfigMap(namespace string) *corev1.ConfigMap {
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
			"ca.crt":  "|\n" + tlsCA,
			"tls.crt": "|\n" + tlsCert,
			"tls.key": "|\n" + tlsPrivKey,
		},
	}
}

func NewOAuthProxyPod(proxyImage string, proxyArgs []string) *corev1.Pod {
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
				{
					Name: "proxy-tls",
					VolumeSource: corev1.VolumeSource{
						Secret: &corev1.SecretVolumeSource{
							SecretName: "proxy-tls",
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
							Name:      "proxy-tls",
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

func NewOAuthProxyService(serviceName, appLabel string, port int32, targetPort int) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: serviceName,
			Labels: map[string]string{
				"app": appLabel,
			},
			Annotations: map[string]string{
				"service.alpha.openshift.io/serving-cert-secret-name": "proxy-tls",
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

func visit(n *html.Node, visitor func(*html.Node)) {
	visitor(n)
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		visit(c, visitor)
	}
}

func GetElementsByTagName(root *html.Node, tagName string) []*html.Node {
	elements := []*html.Node{}
	visit(root, func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == tagName {
			elements = append(elements, n)
		}
	})
	return elements
}

func GetAttr(element *html.Node, attrName string) (string, bool) {
	for _, attr := range element.Attr {
		if attr.Key == attrName {
			return attr.Val, true
		}
	}
	return "", false
}

// NewRequestFromForm builds a request that simulates submitting the given form.
func NewRequestFromForm(form *html.Node, currentURL *url.URL) (*http.Request, error) {
	var (
		reqMethod string
		reqURL    *url.URL
		reqBody   io.Reader
		reqHeader http.Header = http.Header{}
		err       error
	)

	// Method defaults to GET if empty
	if method, _ := GetAttr(form, "method"); len(method) > 0 {
		reqMethod = strings.ToUpper(method)
	} else {
		reqMethod = "GET"
	}

	// URL defaults to current URL if empty
	action, _ := GetAttr(form, "action")
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
	for _, input := range GetElementsByTagName(form, "input") {
		if name, ok := GetAttr(input, "name"); ok {
			if value, ok := GetAttr(input, "value"); ok {
				inputType, _ := GetAttr(input, "type")

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
					if _, checked := GetAttr(input, "checked"); checked {
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
