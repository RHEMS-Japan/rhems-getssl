package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"gopkg.in/yaml.v2"
	"net/http"
	"os"
	"strconv"
	"time"
)

type Info struct { // 証明書情報
	Domains        []string `yaml:"domains"`
	WildcardDomain string   `yaml:"wildcard_domain"`
	WildCardSans   []string `yaml:"wildcard_sans"`
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
		postToBadges(false, "Config not found error", "Please provide the path to the YAML file using -f flag.", 0)
		os.Exit(1)
	}

	// config Fileの読み込み
	yamlData, err := os.ReadFile(yamlFile)
	if err != nil {
		fmt.Println(err.Error())
		postToBadges(false, "Config read error", err.Error(), 0)
		os.Exit(1)
	}

	// yamlファイルの構造体に変換
	var config Config
	if err := yaml.Unmarshal(yamlData, &config); err != nil {
		fmt.Println(err.Error())
		postToBadges(false, "Config parse error", err.Error(), 0)
		os.Exit(1)
	}

	if cloud == "aws" {
		certs, err := getAWSCertARNs()
		if err != nil {
			fmt.Println(err.Error())
			postToBadges(false, "Get aws cert ARNs failed", err.Error(), 0)
			os.Exit(1)
		}
		for _, info := range config.Info {
			var certArns []string
			for _, cert := range *certs {
				fmt.Println(*cert.CertificateArn)
				certArns = append(certArns, *cert.CertificateArn)
			}
			domains := append(info.WildCardSans, info.WildcardDomain)
			domains = append(domains, info.Domains...)
			err = checkAWSCert(certArns, domains)
			if err != nil {
				postToBadges(false, "Delete old certs failed", err.Error(), 0)
				os.Exit(1)
			}
		}

	} else {
		certs, err := getTencentCertIds()
		if err != nil {
			fmt.Println(err.Error())
			postToBadges(false, "Get tencent cert ids failed", err.Error(), 0)
			os.Exit(1)
		}
		for _, info := range config.Info {
			var certIds []string
			for _, cert := range *certs {
				fmt.Println(*cert.CertificateId)
				certIds = append(certIds, *cert.CertificateId)
			}
			domains := append(info.WildCardSans, info.WildcardDomain)
			domains = append(domains, info.Domains...)
			err = checkTencentCert(certIds, domains)
			if err != nil {
				postToBadges(false, "Delete old certs failed", err.Error(), 0)
				os.Exit(1)
			}
		}
	}

	postToBadges(true, "Delete old certs completed", "All old certificates have been deleted successfully.", 0)
}

// Badges API への通知
func postToBadges(status bool, msg string, log string, count int) {
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
		time.Sleep(3 * time.Second)
		if count < 5 {
			fmt.Println("[*] Retry")
			count++
			postToBadges(status, msg, log, count)
		} else {
			fmt.Println("[*] Retry failed")
			os.Exit(1)
		}
	} else {
		fmt.Println("[*] " + res.Status)
	}
}
