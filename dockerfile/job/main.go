package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/acm"
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
	"strings"
	"time"
)

type Info struct {
	Namespace   string   `yaml:"namespace"`
	IngressName string   `yaml:"ingress_name"`
	Domains     []string `yaml:"domains"`
}

type Config struct {
	Info []Info `yaml:"info"`
}

func main() {
	var yamlFile string
	var cloud string
	flag.StringVar(&yamlFile, "f", "config.yml", "Path to the YAML file containing info")
	flag.StringVar(&cloud, "c", "aws", "Cloud provider")
	flag.Parse()

	if yamlFile == "" {
		fmt.Println("Please provide the path to the YAML file using -f flag.")
		os.Exit(1)
	}

	yamlData, err := os.ReadFile(yamlFile)
	if err != nil {
		panic(err.Error())
	}

	var config Config
	if err := yaml.Unmarshal(yamlData, &config); err != nil {
		panic(err.Error())
	}

	clientset := initKubeClient()

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

				uploadCert(domain, cloud)
			} else {
				find := exec.Command("find", "/var/www/html/.well-known/acme-challenge/", "-maxdepth", "1", "-type", "f")
				findOut, _ := find.Output()
				var fullpath string = string(findOut)
				basename := filepath.Base(fullpath)
				cat := exec.Command("cat", fullpath, "2&>1")
				content, _ := cat.Output()

				fmt.Println("content: ", string(content))

				exec.Command("cp", "acme-challenge-base.yml", "acme-challenge.yml").Run()
				exec.Command("cp", "file-name-base.yml", "file-name.yml").Run()
				replaceStringInFile("acme-challenge.yml", "__FILE_NAME__", basename)
				replaceStringInFile("file-name.yml", "__FILE_NAME__", basename)
				replaceStringInFile("file-name.yml", "__CONTENT__", string(content))

				exec.Command("kubectl", "delete", "configmap", "acme-challenge", "-n", os.Getenv("POD_NAMESPACE")).Run()
				exec.Command("kubectl", "delete", "configmap", "file-name", "-n", os.Getenv("POD_NAMESPACE")).Run()
				exec.Command("kubectl", "apply", "-f", "acme-challenge.yml", "-n", os.Getenv("POD_NAMESPACE")).Run()
				exec.Command("kubectl", "apply", "-f", "file-name.yml", "-n", os.Getenv("POD_NAMESPACE")).Run()
				exec.Command("kubectl", "rollout", "restart", "deployment", "rhems-getssl-go", "-n", os.Getenv("POD_NAMESPACE")).Run()

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
					uploadCert(domain, cloud)
				} else {
					fmt.Println("Certificate creation failed")
				}
			}
		}

		ingressInterface := clientset.NetworkingV1().Ingresses(info.Namespace)

		var arn string = "arn:aws:acm:ap-northeast-1:063150541913:certificate/aea2ee79-45c3-44f0-a8e4-c9d6e34fe4ee"
		ingressCertArnPatch := []byte(fmt.Sprintf(`{"metadata":{"annotations":{"alb.ingress.kubernetes.io/certificate-arn":"%s"}}}`, arn))

		retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			_, updateErr := ingressInterface.Patch(context.TODO(), info.IngressName, types.StrategicMergePatchType, ingressCertArnPatch, metav1.PatchOptions{})
			return updateErr
		})
		if retryErr != nil {
			fmt.Printf("Error updating ingress %s: %v\n", info.IngressName, retryErr)
		} else {
			fmt.Printf("Ingress %s updated successfully\n", info.IngressName)
		}
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

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	return clientset
}

func uploadCert(domain string, cloud string) {
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
	}
}

func uploadCertAWS(certificate []byte, privateKey []byte, certificateChain []byte) *string {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		panic(err)
	}

	client := acm.NewFromConfig(cfg)

	input := &acm.ImportCertificateInput{
		Certificate:      certificate, // Required
		PrivateKey:       privateKey,  // Required
		CertificateChain: certificateChain,
	}

	output, err := client.ImportCertificate(context.TODO(), input)
	if err != nil {
		panic(err)
	}

	return output.CertificateArn
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
	for {
		resp, _ := http.Get(url)
		err := resp.Body.Close()
		if err != nil {
			break
		}
		body, _ := io.ReadAll(resp.Body)
		if string(body) == content {
			break
		}
		resp = nil
		time.Sleep(10 * time.Second)
	}
}
