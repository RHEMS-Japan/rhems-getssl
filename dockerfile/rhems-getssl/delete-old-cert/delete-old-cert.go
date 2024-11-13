package main

import (
	"flag"
	"fmt"
	"gopkg.in/yaml.v2"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"os"
	"path/filepath"
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
	WildCardSans   []string  `yaml:"wildcard_sans"`
	CheckDomains   []string  `yaml:"check_domains"`
	Ingresses      []Ingress `yaml:"ingresses"`
	Secrets        []Secret  `yaml:"secrets"`
}

type Config struct { // yamlファイルの構造
	Info                 []Info `yaml:"info"`
	ServerDeploymentName string `yaml:"server_deployment_name"`
}

var yamlFile string
var cloud string

func main() {
	flag.StringVar(&yamlFile, "f", "config.yml", "Path to the YAML file containing info. default '-f config.yml'")
	flag.StringVar(&cloud, "c", "aws", "Cloud provider. default '-c aws'")
	flag.Parse()

	// -f flagの値チェック
	if yamlFile == "" {
		fmt.Println("Please provide the path to the YAML file using -f flag.")
		os.Exit(1)
	}

	// config Fileの読み込み
	yamlData, err := os.ReadFile(yamlFile)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	// yamlファイルの構造体に変換
	var config Config
	if err := yaml.Unmarshal(yamlData, &config); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	if cloud == "aws" {
		certs, err := getAWSCertARNs()
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
		for _, info := range config.Info {
			var certArns []string
			for _, cert := range *certs {
				fmt.Println(*cert.CertificateArn)
				certArns = append(certArns, *cert.CertificateArn)
			}
			domains := append(info.WildCardSans, info.WildcardDomain)
			checkAWSCert(certArns, domains)
		}

	} else {
		certs, err := getTencentCertIds()
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
		for _, info := range config.Info {
			var certIds []string
			for _, cert := range *certs {
				fmt.Println(*cert.CertificateId)
				certIds = append(certIds, *cert.CertificateId)
			}
			domains := append(info.WildCardSans, info.WildcardDomain)
			checkTencentCert(certIds, domains)
		}
	}
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
