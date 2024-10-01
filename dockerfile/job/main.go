package main

import (
	"bytes"
	"context"
	b64 "encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/tencentcloud/tencentcloud-sdk-go-intl-en/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go-intl-en/tencentcloud/common/errors"
	"github.com/tencentcloud/tencentcloud-sdk-go-intl-en/tencentcloud/common/profile"
	ssl "github.com/tencentcloud/tencentcloud-sdk-go-intl-en/tencentcloud/ssl/v20191205"
	"gopkg.in/yaml.v2"
	"io"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Info struct {
	Namespace   string   `yaml:"namespace"`
	IngressName string   `yaml:"ingress_name"`
	SecretName  string   `yaml:"secret_name"`
	Domains     []string `yaml:"domains"`
}

type Config struct {
	Info []Info `yaml:"info"`
}

type Badges struct {
	ApiToken     string `json:"api_token"`
	Organization string `json:"organization"`
	Repo         string `json:"repo"`
	App          string `json:"app"`
	Branch       string `json:"branch"`
	Status       bool   `json:"status"`
	Update       string `json:"update"`
	Cronjob      string `json:"cronjob"`
	GraceTime    int    `json:"grace_time"`
	SlackFailed  string `json:"slack_failed"`
	SlackSuccess string `json:"slack_success"`
	Msg          string `json:"msg"`
	Log          string `json:"log"`
}

func main() {
	var yamlFile string
	var cloud string
	var init string
	flag.StringVar(&yamlFile, "f", "config.yml", "Path to the YAML file containing info")
	flag.StringVar(&cloud, "c", "aws", "Cloud provider")
	flag.StringVar(&init, "i", "false", "Initialize")
	flag.Parse()

	if yamlFile == "" {
		fmt.Println("Please provide the path to the YAML file using -f flag.")
		postToBadges(false, "Please provide the path to the YAML file using -f flag.", "config file not found")
		os.Exit(1)
	}

	yamlData, err := os.ReadFile(yamlFile)
	if err != nil {
		fmt.Println(err.Error())
		postToBadges(false, err.Error(), "config file read error")
		os.Exit(1)
	}

	var config Config
	if err := yaml.Unmarshal(yamlData, &config); err != nil {
		fmt.Println(err.Error())
		postToBadges(false, err.Error(), "config file unmarshal error")
		os.Exit(1)
	}

	if init == "true" {
		fmt.Println("Initialize")
		for _, info := range config.Info {
			fmt.Println("Namespace: ", info.Namespace)
			fmt.Println("Ingress Name: ", info.IngressName)
			fmt.Println("Domains: ", info.Domains)

			for _, domain := range info.Domains {
				cmd := exec.Command("/tmp/init.sh", domain)
				output, err := cmd.Output()
				if err != nil {
					fmt.Println(err.Error())
					postToBadges(false, "init.sh error", err.Error())
					os.Exit(1)
				}
				fmt.Println("Output: \n", string(output))
			}
		}
		os.Exit(0)
	}

	clientSet := initKubeClient()

	for _, info := range config.Info {
		fmt.Println("Namespace: ", info.Namespace)
		fmt.Println("Ingress Name: ", info.IngressName)
		fmt.Println("Domains: ", info.Domains)

		for _, domain := range info.Domains {
			getssl := exec.Command("./getssl", "-f", domain)
			out, _ := getssl.Output()

			fmt.Println("Output: ", string(out))
			var getsslOutput string = string(out)

			pattern := `.*Verification\scompleted,\sobtaining\scertificate.*`
			match, _ := regexp.MatchString(pattern, getsslOutput)

			if match {
				fmt.Println("Certificate created successfully\ncertificate upload to cert manager")

				uploadCert(domain, cloud, info.SecretName, clientSet)
			} else {
				find := exec.Command("find", "/var/www/html/.well-known/acme-challenge/", "-maxdepth", "1", "-type", "f")
				findOut, _ := find.Output()
				var fullpath string = string(findOut)
				basename := filepath.Base(fullpath)
				content, err := os.ReadFile(strings.TrimSuffix(fullpath, "\n"))
				if err != nil {
					fmt.Println(err.Error())
					postToBadges(false, "acme-challenge file read error", err.Error())
					os.Exit(1)
				}

				fmt.Println("content: ", string(content))

				exec.Command("cp", "acme-challenge-base.yml", "acme-challenge.yml").Run()
				exec.Command("cp", "file-name-base.yml", "file-name.yml").Run()
				replaceStringInFile("acme-challenge.yml", "__FILE_NAME__", basename)
				replaceStringInFile("acme-challenge.yml", "__CONTENT__", string(content))
				replaceStringInFile("file-name.yml", "__FILE_NAME__", basename)

				err = exec.Command("kubectl", "delete", "configmap", "acme-challenge", "-n", os.Getenv("POD_NAMESPACE")).Run()
				if err != nil {
					fmt.Println(err.Error())
					postToBadges(false, "acme-challenge configmap delete error", err.Error())
					os.Exit(1)
				}
				err = exec.Command("kubectl", "delete", "configmap", "file-name", "-n", os.Getenv("POD_NAMESPACE")).Run()
				if err != nil {
					fmt.Println(err.Error())
					postToBadges(false, "file-name configmap delete error", err.Error())
					os.Exit(1)
				}
				err = exec.Command("kubectl", "apply", "-f", "acme-challenge.yml", "-n", os.Getenv("POD_NAMESPACE")).Run()
				if err != nil {
					fmt.Println(err.Error())
					postToBadges(false, "acme-challenge configmap apply error", err.Error())
					os.Exit(1)
				}
				err = exec.Command("kubectl", "apply", "-f", "file-name.yml", "-n", os.Getenv("POD_NAMESPACE")).Run()
				if err != nil {
					fmt.Println(err.Error())
					postToBadges(false, "file-name configmap apply error", err.Error())
					os.Exit(1)
				}
				err = exec.Command("kubectl", "rollout", "restart", "deployment", "rhems-getssl-go", "-n", os.Getenv("POD_NAMESPACE")).Run()
				if err != nil {
					fmt.Println(err.Error())
					postToBadges(false, "rhems-getssl-go deployment restart error", err.Error())
					os.Exit(1)
				}

				var url string = fmt.Sprintf("http://%s/.well-known/acme-challenge/%s", domain, basename)
				waitAvailable(url, string(content))

				getsslAgain := exec.Command("./getssl", "-f", domain)
				getsslAgainOut, _ := getsslAgain.Output()

				fmt.Println("Output: ", string(getsslAgainOut))
				var getsslAgainOutput string = string(getsslAgainOut)

				patternAgain := `.*Certificate\ssaved\sin.*`
				matchAgain, _ := regexp.MatchString(patternAgain, getsslAgainOutput)

				if matchAgain {
					fmt.Println("Certificate creation successful")
					uploadCert(domain, cloud, info.SecretName, clientSet)
				} else {
					fmt.Println("Certificate creation failed")
				}
			}
		}

		//ingressInterface := clientSet.NetworkingV1().Ingresses(info.Namespace)
		//
		//var arn string = "arn:aws:acm:ap-northeast-1:063150541913:certificate/aea2ee79-45c3-44f0-a8e4-c9d6e34fe4ee"
		//ingressCertArnPatch := []byte(fmt.Sprintf(`{"metadata":{"annotations":{"alb.ingress.kubernetes.io/certificate-arn":"%s"}}}`, arn))
		//
		//retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		//	_, updateErr := ingressInterface.Patch(context.TODO(), info.IngressName, types.StrategicMergePatchType, ingressCertArnPatch, metav1.PatchOptions{})
		//	return updateErr
		//})
		//if retryErr != nil {
		//	fmt.Printf("Error updating ingress %s: %v\n", info.IngressName, retryErr)
		//} else {
		//	fmt.Printf("Ingress %s updated successfully\n", info.IngressName)
		//}
	}
}

func initKubeClient() *kubernetes.Clientset {
	var kubeconfig *string
	var config *rest.Config
	var err error

	home := os.Getenv("HOME")
	if home != "" {
		kubeconfigPath := filepath.Join(home, ".kube", "config")
		if _, err := os.Stat(kubeconfigPath); err == nil {
			kubeconfig = flag.String("k", kubeconfigPath, "absolute path to the kubeconfig file")
		}
	}

	flag.Parse()

	if kubeconfig != nil {
		config, err = clientcmd.BuildConfigFromFlags("", *kubeconfig)
		if err != nil {
			panic(err.Error())
		}
	} else {
		config, err = rest.InClusterConfig()
		if err != nil {
			panic(err.Error())
		}
	}

	clientSet, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	return clientSet
}

func uploadCert(domain string, cloud string, secretName string, clientSet *kubernetes.Clientset) {
	certPath := fmt.Sprintf("/root/.getssl/%s/%s.crt", domain, domain)
	privateKeyPath := fmt.Sprintf("/root/.getssl/%s/%s.key", domain, domain)
	certChainPath := fmt.Sprintf("/root/.getssl/%s/chain.crt", domain)

	cert, err := os.ReadFile(certPath)
	if err != nil {
		panic(err)
	}
	privateKet, err := os.ReadFile(privateKeyPath)
	if err != nil {
		panic(err)
	}
	certChain, err := os.ReadFile(certChainPath)
	if err != nil {
		panic(err)
	}
	if cloud == "aws" {
		arn := uploadCertAWS(cert, privateKet, certChain)

		fmt.Println("Certificate uploaded successfully")
		fmt.Println("Certificate ARN: ", *arn)

		postToBadges(true, "Certificate uploaded successfully", "Certificate ARN: "+*arn)
	} else {
		response := uploadCertTencent(cert, privateKet)

		fmt.Println("Certificate uploaded successfully")
		fmt.Println("Certificate response: ", response.ToJsonString())

		editCertSecret(*response.Response.CertificateId, secretName, clientSet)

		postToBadges(true, "Certificate uploaded successfully", "Certificate ID: "+*response.Response.CertificateId)
	}
}

func uploadCertAWS(certificate []byte, privateKey []byte, certificateChain []byte) *string {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Println(err.Error())
		postToBadges(false, "awscli load config error", err.Error())
		os.Exit(1)
	}

	client := acm.NewFromConfig(cfg)

	input := &acm.ImportCertificateInput{
		Certificate:      certificate, // Required
		PrivateKey:       privateKey,  // Required
		CertificateChain: certificateChain,
	}

	output, err := client.ImportCertificate(context.TODO(), input)
	if err != nil {
		fmt.Println(err.Error())
		postToBadges(false, "Certificate upload error", err.Error())
		os.Exit(1)
	}

	return output.CertificateArn
}

func uploadCertTencent(certificate []byte, privateKey []byte) *ssl.UploadCertificateResponse {
	// Required steps:
	// Instantiate an authentication object. The Tencent Cloud account key pair `secretId` and `secretKey` need to be passed in as the input parameters
	// This example uses the way to read from the environment variable, so you need to set these two values in the environment variable in advance
	// You can also write the key pair directly into the code, but be careful not to copy, upload, or share the code to others
	// Query the CAM key: https://console.tencentcloud.com/capi
	credential := common.NewCredential(os.Getenv("TENCENTCLOUD_SECRET_ID"), os.Getenv("TENCENTCLOUD_SECRET_KEY"))
	// Optional steps:
	// Instantiate a client configuration object. You can specify the timeout period and other configuration items
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "ssl.tencentcloudapi.com"
	// Instantiate an client object
	// The second parameter is the region information. You can directly enter the string "ap-guangzhou" or import the preset constant
	client, _ := ssl.NewClient(credential, os.Getenv("TENCENTCLOUD_REGION"), cpf)

	// Instantiate a request object. You can further set the request parameters according to the API called and actual conditions
	request := ssl.NewUploadCertificateRequest()

	request.CertificatePublicKey = common.StringPtr(string(certificate))
	request.CertificatePrivateKey = common.StringPtr(string(privateKey))

	// The returned "resp" is an instance of the UploadCertificateResponse class which corresponds to the request object
	response, err := client.UploadCertificate(request)
	if _, ok := err.(*errors.TencentCloudSDKError); ok {
		fmt.Printf("An API error has returned: %s", err)
		postToBadges(false, "tencent api error", fmt.Sprintf("An API error has returned: %s", err))
		os.Exit(1)
	}
	// A string return packet in JSON format is output

	return response
}

func editCertSecret(certificateId string, secretName string, clientSet *kubernetes.Clientset) {
	secretInterface := clientSet.CoreV1().Secrets(os.Getenv("POD_NAMESPACE"))

	var certIdBase64 string = b64.StdEncoding.EncodeToString([]byte(certificateId))
	secretPatch := []byte(fmt.Sprintf(`{"data":{"qcloud_cert_id":"%s"}}`, certIdBase64))

	retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		_, updateErr := secretInterface.Patch(context.TODO(), secretName, types.StrategicMergePatchType, secretPatch, metav1.PatchOptions{})
		return updateErr
	})
	if retryErr != nil {
		fmt.Printf("Error updating ingress %s: %v\n", secretName, retryErr)
		postToBadges(false, "secret patch error", retryErr.Error())
	} else {
		fmt.Printf("Secret %s updated successfully\n", secretName)
	}
}

func replaceStringInFile(filename string, old string, new string) {
	input, err := os.ReadFile(filename)
	if err != nil {
		panic(err)
	}

	contents := string(input)

	contents = strings.ReplaceAll(contents, old, strings.TrimSuffix(new, "\n"))

	err = os.WriteFile(filename, []byte(contents), os.ModePerm)
	if err != nil {
		panic(err)
	}
}

func waitAvailable(url string, content string) {
	// Wait for the file to be available
	var resp *http.Response
	var body []byte
	var err error
	for {
		resp, err = http.Get(strings.TrimSuffix(url, "\n"))
		if err != nil {
			fmt.Println("err", err)
		}
		body, err = io.ReadAll(resp.Body)
		if err != nil {
			fmt.Println("err", err)
			break
		}
		fmt.Println("body", strings.TrimSuffix(string(body), "\n"))
		fmt.Println("content", content)
		if strings.TrimSuffix(string(body), "\n") == content {
			fmt.Println("File available")
			break
		}
		err = resp.Body.Close()
		if err != nil {
			break
		}
		resp = nil
		body = nil
		err = nil
		fmt.Println("File not available yet")
		time.Sleep(10 * time.Second)
	}
}

func postToBadges(status bool, msg string, log string) {
	graceTime, err := strconv.Atoi(os.Getenv("GRACE_TIME"))
	if err != nil {
		graceTime = 3
	}
	date := time.Now().Format("2006-01-02-15-04-05")

	badges := Badges{
		ApiToken:     os.Getenv("API_TOKEN"),
		Organization: os.Getenv("ORGANIZATION"),
		Repo:         os.Getenv("REPO"),
		App:          os.Getenv("APP"),
		Branch:       os.Getenv("BRANCH"),
		Status:       status,
		Update:       date,
		Cronjob:      os.Getenv("CRON"),
		GraceTime:    graceTime,
		SlackFailed:  os.Getenv("SLACK_FAILED"),
		SlackSuccess: os.Getenv("SLACK_SUCCESS"),
		Msg:          msg,
		Log:          log,
	}

	json, _ := json.Marshal(badges)
	fmt.Printf("[+] %s\n", string(json))

	res, err := http.Post("https://badges.rhems-japan.com/api-update-badge", "application/json", bytes.NewBuffer(json))
	defer res.Body.Close()

	if err != nil {
		fmt.Println("[!] " + err.Error())
		os.Exit(1)
	} else {
		fmt.Println("[*] " + res.Status)
	}
}
