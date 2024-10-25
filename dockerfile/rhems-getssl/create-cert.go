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

type Secret struct { // TKE用Secret 設定
	Namespace  string `yaml:"namespace"`
	SecretName string `yaml:"secret_name"`
}

type Ingress struct { // EKS用Ingress 設定
	Namespace   string `yaml:"namespace"`
	IngressName string `yaml:"ingress_name"`
}

type Info struct { // 証明書情報
	Namespace      string    `yaml:"namespace"`
	IngressName    string    `yaml:"ingress_name"`
	SecretName     string    `yaml:"secret_name"`
	Domains        []string  `yaml:"domains"`
	WildcardDomain string    `yaml:"wildcard_domain"`
	CheckDomains   []string  `yaml:"check_domains"`
	Ingresses      []Ingress `yaml:"ingresses"`
	Secrets        []Secret  `yaml:"secrets"`
}

type Config struct { // yamlファイルの構造
	Info                 []Info `yaml:"info"`
	ServerDeploymentName string `yaml:"server_deployment_name"`
}

type Badges struct { // RHEMS Badges API 用
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

var yamlFile string               // -f flag
var cloud string                  // -c flag
var initialize bool               // -i flag
var force bool                    // -force flag
var updateBeforeDay int           // -update-before-day flag
var letsEncryptEnvironment string // -lets-encrypt-environment flag
var dnsValidation bool            // -dns-validation flag

func main() {
	// 実行フラグ取得
	flag.StringVar(&yamlFile, "f", "config.yml", "Path to the YAML file containing info. default '-f config.yml'")
	flag.StringVar(&cloud, "c", "aws", "Select cloud provider aws or tencent. default '-c aws'")
	flag.BoolVar(&initialize, "i", false, "Initialize create-cert")
	flag.BoolVar(&force, "force", false, "Force cert update even if it is not expired. default '-force=false'")
	flag.IntVar(&updateBeforeDay, "update-before-day", 3, "Update before date. default '-update-before-day 3'")
	flag.StringVar(&letsEncryptEnvironment, "lets-encrypt-environment", "production", "Let's Encrypt environment production or staging. default '-lets-encrypt-environment production'")
	flag.BoolVar(&dnsValidation, "dns-validation", false, "DNS validation. default '-dns-validation=false'")
	flag.Parse()

	// -update-before-day flagの値チェック
	if updateBeforeDay < 0 {
		fmt.Println("Update before day must be greater than or equal to 0.")
		postToBadges(os.Getenv("BRANCH"), false, "Update before day must be greater than or equal to 0.", "update before day error", 0)
		os.Exit(1)
	}

	// -f flagの値チェック
	if yamlFile == "" {
		fmt.Println("Please provide the path to the YAML file using -f flag.")
		postToBadges(os.Getenv("BRANCH"), false, "Please provide the path to the YAML file using -f flag.", "config file not found", 0)
		os.Exit(1)
	}

	// config Fileの読み込み
	yamlData, err := os.ReadFile(yamlFile)
	if err != nil {
		fmt.Println(err.Error())
		postToBadges(os.Getenv("BRANCH"), false, err.Error(), "config file read error", 0)
		os.Exit(1)
	}

	// yamlファイルの構造体に変換
	var config Config
	if err := yaml.Unmarshal(yamlData, &config); err != nil {
		fmt.Println(err.Error())
		postToBadges(os.Getenv("BRANCH"), false, err.Error(), "config file unmarshal error", 0)
		os.Exit(1)
	}

	// Kubernetes Clientの初期化
	clientSet := initKubeClient()

	// 初期化処理
	if initialize {
		initGetssl(config, clientSet)
	}

	// 証明書更新処理
	for _, info := range config.Info {
		fmt.Println("Namespace: ", info.Namespace)
		fmt.Println("Ingress Name: ", info.IngressName)
		fmt.Println("Domains: ", info.Domains)

		if info.WildcardDomain != "" {
			if !force {
				for _, checkDomain := range info.CheckDomains {
					if checkCertValidation(checkDomain) {
						continue
					} else {
						createWildCert(info, info.WildcardDomain, clientSet)
						break
					}
				}
			} else {
				createWildCert(info, info.WildcardDomain, clientSet)
			}
		} else {
			for _, domain := range info.Domains {
				if !force {
					if checkCertValidation(domain) {
						continue
					} else {
						createCert(info, domain, clientSet)
					}
				} else {
					createCert(info, domain, clientSet)
				}
			}
		}
	}

	// DNS validationが無効の場合、Goサーバーのレプリカ数を0に戻す
	if !dnsValidation {
		if config.ServerDeploymentName == "" {
			fmt.Println("Server Deployment Name is not provided. use default name 'rhems-getssl-go'.")
			config.ServerDeploymentName = "rhems-getssl-go"
		}
		editDeployment(0, clientSet, os.Getenv("POD_NAMESPACE"), config.ServerDeploymentName)
	}

	// 全ての証明書が更新された場合、Badgesに通知
	postToBadges(os.Getenv("BRANCH"), true, "All certificates are up to date", "All certificates are up to date", 0)
}

// 初期化処理
func initGetssl(config Config, clientSet *kubernetes.Clientset) {
	fmt.Println("Initialize")

	// DNS validationが無効の場合、Goサーバーのレプリカ数を1に変更
	if !dnsValidation {
		if config.ServerDeploymentName == "" {
			fmt.Println("Server Deployment Name is not provided. use default name 'rhems-getssl-go'.")
			config.ServerDeploymentName = "rhems-getssl-go"
		}
		editDeployment(1, clientSet, os.Getenv("POD_NAMESPACE"), config.ServerDeploymentName)
	}

	// getsslの初期化処理
	for _, info := range config.Info {
		fmt.Println("Namespace: ", info.Namespace)
		fmt.Println("Ingress Name: ", info.IngressName)
		fmt.Println("Secret Name: ", info.SecretName)
		fmt.Println("Domains: ", info.Domains)

		for _, domain := range info.Domains {
			cmd := exec.Command("/tmp/init.sh", domain, letsEncryptEnvironment)
			output, err := cmd.CombinedOutput()
			if err != nil {
				fmt.Println(err.Error())
				postToBadges(domain, false, "init.sh error", string(output), 0)
				os.Exit(1)
			}
			fmt.Println("Output: \n", string(output))
		}

		if info.WildcardDomain != "" {
			cmd := exec.Command("/tmp/init.sh", info.WildcardDomain, letsEncryptEnvironment)
			output, err := cmd.CombinedOutput()
			if err != nil {
				fmt.Println(err.Error())
				postToBadges(info.WildcardDomain, false, "init.sh error", string(output), 0)
				os.Exit(1)
			}
			fmt.Println("Output: \n", string(output))
		}
	}

	// DNS validationが有効の場合、Route53変更のためのスクリプトを設定
	if dnsValidation {
		if letsEncryptEnvironment == "production" {
			replaceStringInFile("/root/.getssl/getssl.cfg", "CA=\"https://acme-staging-v02.api.letsencrypt.org\"", "CA=\"https://acme-v02.api.letsencrypt.org\"")
		}
		replaceStringInFile("/root/.getssl/getssl.cfg", "#VALIDATE_VIA_DNS=\"true\"", "VALIDATE_VIA_DNS=\"true\"")
		replaceStringInFile("/root/.getssl/getssl.cfg", "#VALIDATE_VIA_DNS=\"true\"", "VALIDATE_VIA_DNS=\"true\"")
		replaceStringInFile("/root/.getssl/getssl.cfg", "#DNS_ADD_COMMAND=", "DNS_ADD_COMMAND=\"/root/dns_add_route53\"")
		replaceStringInFile("/root/.getssl/getssl.cfg", "#DNS_DEL_COMMAND=", "DNS_DEL_COMMAND=\"/root/dns_remove_route53\"")
	}

	os.Exit(0)
}

// Kubernetes Clientの初期化
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

// 証明書アップロード処理
func uploadCert(domain string, cloud string) string {
	// getsslで作成された証明書ファイルのパス
	certPath := fmt.Sprintf("/root/.getssl/%s/%s.crt", domain, domain)
	fullCertChainPath := fmt.Sprintf("/root/.getssl/%s/%s_chain.pem", domain, domain)
	privateKeyPath := fmt.Sprintf("/root/.getssl/%s/%s.key", domain, domain)
	certChainPath := fmt.Sprintf("/root/.getssl/%s/chain.crt", domain)

	// 証明書ファイルの読み込み
	cert, err := os.ReadFile(certPath)
	if err != nil {
		fmt.Println(err.Error())
		postToBadges(domain, false, "cert file read error", err.Error(), 0)
		os.Exit(1)
	}
	privateKey, err := os.ReadFile(privateKeyPath)
	if err != nil {
		fmt.Println(err.Error())
		postToBadges(domain, false, "private key file read error", err.Error(), 0)
		os.Exit(1)
	}
	certChain, err := os.ReadFile(certChainPath)
	if err != nil {
		fmt.Println(err.Error())
		postToBadges(domain, false, "chain file read error", err.Error(), 0)
		os.Exit(1)
	}
	fullCertChain, err := os.ReadFile(fullCertChainPath)
	if err != nil {
		fmt.Println(err.Error())
		postToBadges(domain, false, "full chain file read error", err.Error(), 0)
		os.Exit(1)
	}

	// AWS or Tencent Cloud に証明書をアップロード
	if cloud == "aws" {
		arn := uploadCertAWS(domain, cert, privateKey, certChain)

		fmt.Println("Certificate uploaded successfully")
		fmt.Println("Certificate ARN: ", *arn)

		return *arn
	} else {
		response := uploadCertTencent(domain, fullCertChain, privateKey)

		fmt.Println("Certificate uploaded successfully")
		fmt.Println("Certificate response: ", response.ToJsonString())

		return *response.Response.CertificateId
	}
}

// AWSに証明書をアップロード
func uploadCertAWS(domain string, certificate []byte, privateKey []byte, certificateChain []byte) *string {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Println(err.Error())
		postToBadges(domain, false, "awscli load config error", err.Error(), 0)
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
		postToBadges(domain, false, "Certificate upload error", err.Error(), 0)
		os.Exit(1)
	}

	return output.CertificateArn
}

// Tencent Cloudに証明書をアップロード
func uploadCertTencent(domain string, certificate []byte, privateKey []byte) *ssl.UploadCertificateResponse {
	credential := common.NewCredential(os.Getenv("TENCENTCLOUD_SECRET_ID"), os.Getenv("TENCENTCLOUD_SECRET_KEY"))

	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "ssl.tencentcloudapi.com"

	client, _ := ssl.NewClient(credential, os.Getenv("TENCENTCLOUD_REGION"), cpf)

	request := ssl.NewUploadCertificateRequest()

	request.CertificatePublicKey = common.StringPtr(string(certificate))
	request.CertificatePrivateKey = common.StringPtr(string(privateKey))

	response, err := client.UploadCertificate(request)
	if _, ok := err.(*errors.TencentCloudSDKError); ok {
		fmt.Printf("An API error has returned: %s", err)
		postToBadges(domain, false, "tencent api error", fmt.Sprintf("An API error has returned: %s", err), 0)
		os.Exit(1)
	}

	return response
}

// TKE用証明書IDSecretの作成、更新
func editCertSecret(domain string, certificateId string, secretName string, namespace string) {
	exec.Command("rm", "secret.yml").Run()
	exec.Command("cp", "secret-base.yml", "secret.yml").Run()
	replaceStringInFile("secret.yml", "__SECRET_NAME__", secretName)
	replaceStringInFile("secret.yml", "__QCLOUD_CERT_ID__", b64.StdEncoding.EncodeToString([]byte(certificateId)))

	output, err := exec.Command("kubectl", "apply", "-f", "secret.yml", "-n", namespace).CombinedOutput()
	if err != nil {
		fmt.Println(string(output))
		postToBadges(domain, false, "secret.yml apply error", string(output), 0)
		os.Exit(1)
	}
}

// EKS用証明書ARNのIngressへの適用
func editIngress(domain string, clientSet *kubernetes.Clientset, namespace string, ingressName string, arn string) {
	ingressInterface := clientSet.NetworkingV1().Ingresses(namespace)

	ingressCertArnPatch := []byte(fmt.Sprintf(`{"metadata":{"annotations":{"alb.ingress.kubernetes.io/certificate-arn":"%s"}}}`, arn))

	retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		_, updateErr := ingressInterface.Patch(context.TODO(), ingressName, types.StrategicMergePatchType, ingressCertArnPatch, metav1.PatchOptions{})
		return updateErr
	})
	if retryErr != nil {
		fmt.Printf("Error updating ingress %s: %v\n", ingressName, retryErr)
		postToBadges(domain, false, "ingress patch error", retryErr.Error(), 0)
		os.Exit(1)
	} else {
		fmt.Printf("Ingress %s updated successfully\n", ingressName)
	}
}

// Deploymentのレプリカ数変更
func editDeployment(replicas int, clientSet *kubernetes.Clientset, namespace string, deploymentName string) {
	deploymentInterface := clientSet.AppsV1().Deployments(namespace)

	deploymentPatch := []byte(fmt.Sprintf(`{"spec":{"replicas":%d}}`, replicas))

	retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		_, updateErr := deploymentInterface.Patch(context.TODO(), deploymentName, types.StrategicMergePatchType, deploymentPatch, metav1.PatchOptions{})
		return updateErr
	})
	if retryErr != nil {
		fmt.Printf("Error updating deployment %s: %v\n", deploymentName, retryErr)
		postToBadges(os.Getenv("BRANCH"), false, "deployment patch error", retryErr.Error(), 0)
		os.Exit(1)
	} else {
		fmt.Printf("Deployment %s updated successfully\n", deploymentName)
	}
}

// ファイルの置換
func replaceStringInFile(filename string, old string, new string) {
	input, err := os.ReadFile(filename)
	if err != nil {
		fmt.Println("Error reading file", err)
		postToBadges(os.Getenv("BRANCH"), false, "Error reading file", err.Error(), 0)
		os.Exit(1)
	}

	contents := string(input)

	contents = strings.ReplaceAll(contents, old, strings.TrimSuffix(new, "\n"))

	err = os.WriteFile(filename, []byte(contents), os.ModePerm)
	if err != nil {
		fmt.Println("Error writing file", err)
		postToBadges(os.Getenv("BRANCH"), false, "Error writing file", err.Error(), 0)
		os.Exit(1)
	}
}

// ファイル認証の待機
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

// Badges API への通知
func postToBadges(app string, status bool, msg string, log string, count int) {
	graceTime, err := strconv.Atoi(os.Getenv("GRACE_TIME"))
	if err != nil {
		graceTime = 3
	}
	date := time.Now().Format("2006-01-02-15-04-05")

	badges := Badges{
		ApiToken:     os.Getenv("API_TOKEN"),
		Organization: os.Getenv("ORGANIZATION"),
		Repo:         os.Getenv("REPO"),
		App:          app,
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
		time.Sleep(3 * time.Second)
		if count < 5 {
			fmt.Println("[*] Retry")
			count++
			postToBadges(app, status, msg, log, count)
		} else {
			fmt.Println("[*] Retry failed")
			os.Exit(1)
		}
	} else {
		fmt.Println("[*] " + res.Status)
	}
}

// 証明書の有効期限チェック
func checkCertValidation(url string) bool {
	res, err := http.Get("https://" + url)

	if err != nil {
		fmt.Println("cert validation error: ", err)
		postToBadges(url, false, "Cert validation error", err.Error(), 0)
		os.Exit(1)
	}

	expireTime := res.TLS.PeerCertificates[0].NotAfter
	expireJSTTime := expireTime.In(time.FixedZone("Asia/Tokyo", 9*60*60))
	expireDate := fmt.Sprintf("%s UTC", expireTime.Format("2006-01-02 15:04:05"))
	expireJSTDate := fmt.Sprintf("%s JST", expireJSTTime.Format("2006-01-02 15:04:05"))

	fmt.Println("Domain: ", url)
	fmt.Println("Expire Time: ", expireTime)
	fmt.Println("Expire JST Time: ", expireJSTTime)
	fmt.Println("Expire Date: ", expireDate)
	fmt.Println("Expire JST Date: ", expireJSTDate)
	fmt.Println("Update Before Day: ", updateBeforeDay)
	fmt.Println("しきい値: ", expireTime.Add(-24*time.Duration(updateBeforeDay)*time.Hour))

	if time.Now().After(expireTime.Add(-24 * time.Duration(updateBeforeDay) * time.Hour)) {
		fmt.Println("Certificate needs to be updated")
		return false
	} else {
		fmt.Println("Certificate is still valid")
		postToBadges(url, true, "Certificate is still valid", fmt.Sprintf("Expire Date: %s", expireDate), 0)
		return true
	}
}

// 証明書の作成と適用
func createCert(info Info, domain string, clientSet *kubernetes.Clientset) {
	fmt.Println("Domain: ", domain)

	getssl := exec.Command("./getssl", "-f", domain)
	out, _ := getssl.CombinedOutput()

	fmt.Println("Output: ", string(out))
	var getsslOutput string = string(out)

	pattern := `.*Verification\scompleted,\sobtaining\scertificate.*`
	match, _ := regexp.MatchString(pattern, getsslOutput)

	if match {
		fmt.Println("Certificate created successfully\ncertificate upload to cert manager")

		certId := uploadCert(domain, cloud)
		applyCertToIngress(certId, domain, clientSet, info.Namespace, info.IngressName, info.SecretName)
	} else {
		find := exec.Command("find", "/var/www/html/.well-known/acme-challenge/", "-maxdepth", "1", "-type", "f")
		findOut, _ := find.CombinedOutput()
		fmt.Println("Output: ", string(findOut))
		var fullpath string = string(findOut)
		fmt.Println("fullpath: ", fullpath)
		basename := filepath.Base(fullpath)
		content, err := os.ReadFile(strings.TrimSuffix(fullpath, "\n"))
		if err != nil {
			fmt.Println(err.Error())
			postToBadges(domain, false, "acme-challenge file read error", err.Error(), 0)
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
			postToBadges(domain, false, "acme-challenge configmap delete error", err.Error(), 0)
			os.Exit(1)
		}
		err = exec.Command("kubectl", "delete", "configmap", "file-name", "-n", os.Getenv("POD_NAMESPACE")).Run()
		if err != nil {
			fmt.Println(err.Error())
			postToBadges(domain, false, "file-name configmap delete error", err.Error(), 0)
			os.Exit(1)
		}
		err = exec.Command("kubectl", "apply", "-f", "acme-challenge.yml", "-n", os.Getenv("POD_NAMESPACE")).Run()
		if err != nil {
			fmt.Println(err.Error())
			postToBadges(domain, false, "acme-challenge configmap apply error", err.Error(), 0)
			os.Exit(1)
		}
		err = exec.Command("kubectl", "apply", "-f", "file-name.yml", "-n", os.Getenv("POD_NAMESPACE")).Run()
		if err != nil {
			fmt.Println(err.Error())
			postToBadges(domain, false, "file-name configmap apply error", err.Error(), 0)
			os.Exit(1)
		}
		err = exec.Command("kubectl", "rollout", "restart", "deployment", "rhems-getssl-go", "-n", os.Getenv("POD_NAMESPACE")).Run()
		if err != nil {
			fmt.Println(err.Error())
			postToBadges(domain, false, "rhems-getssl-go deployment restart error", err.Error(), 0)
			os.Exit(1)
		}

		var url string = fmt.Sprintf("http://%s/.well-known/acme-challenge/%s", domain, basename)
		waitAvailable(url, string(content))

		getsslAgain := exec.Command("./getssl", "-f", domain)
		getsslAgainOut, _ := getsslAgain.CombinedOutput()

		fmt.Println("Output: ", string(getsslAgainOut))
		var getsslAgainOutput string = string(getsslAgainOut)

		patternAgain := `.*Certificate\ssaved\sin.*`
		matchAgain, _ := regexp.MatchString(patternAgain, getsslAgainOutput)

		if matchAgain {
			fmt.Println("Certificate creation successful")
			certId := uploadCert(domain, cloud)
			applyCertToIngress(certId, domain, clientSet, info.Namespace, info.IngressName, info.SecretName)
		} else {
			fmt.Println("Certificate creation failed")
			postToBadges(domain, false, "Certificate creation failed", getsslAgainOutput, 0)
			os.Exit(1)
		}
	}
}

// DNS認証によるwildcard証明書の作成と適用
func createWildCert(info Info, domain string, clientSet *kubernetes.Clientset) {
	fmt.Println("Domain: ", domain)

	getssl := exec.Command("./getssl", "-f", domain)
	out, _ := getssl.CombinedOutput()

	fmt.Println("Output: ", string(out))
	var getsslOutput string = string(out)

	pattern := `.*Verification\scompleted,\sobtaining\scertificate.*`
	match, _ := regexp.MatchString(pattern, getsslOutput)

	if match {
		fmt.Println("Certificate created successfully\ncertificate upload to cert manager")
		certId := uploadCert(domain, cloud)
		for _, ingress := range info.Ingresses {
			applyCertToIngress(certId, domain, clientSet, ingress.Namespace, ingress.IngressName, "")
		}
		for _, secret := range info.Secrets {
			applyCertToIngress(certId, domain, clientSet, secret.Namespace, "", secret.SecretName)
		}
	} else {
		fmt.Println("Certificate creation failed")
		postToBadges(domain, false, "Certificate creation failed", getsslOutput, 0)
		os.Exit(1)
	}
}

// 証明書の適用
func applyCertToIngress(certId string, domain string, clientSet *kubernetes.Clientset, namespace string, ingressName string, secretName string) {
	if cloud == "aws" {
		fmt.Println("Certificate ARN: ", certId)
		editIngress(domain, clientSet, namespace, ingressName, certId)
		postToBadges(domain, true, "Certificate uploaded successfully", "Certificate ARN: "+certId, 0)
	} else {
		fmt.Println("Certificate ID: ", certId)
		editCertSecret(domain, certId, secretName, namespace)
		postToBadges(domain, true, "Certificate uploaded successfully", "Certificate ID: "+certId, 0)
	}
}
