package main

import (
	"context"
	"encoding/json"
	"fmt"
	"google.golang.org/api/dns/v1"
	"google.golang.org/api/option"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"
)

type GoogleCloudServiceAccount struct {
	ProjectId string `json:"project_id"`
}

var basename string
var fqdn string
var challenge string

func main() {
	basename = filepath.Base(os.Args[0])
	serviceKeyAccountFile := os.Args[1]
	fqdn = os.Args[2]
	challenge = os.Args[3]

	jsonFile, err := os.ReadFile(serviceKeyAccountFile)
	if err != nil {
		fmt.Println("Error reading service account file:", err)
		os.Exit(1)
	}

	var serviceAccount GoogleCloudServiceAccount
	err = json.Unmarshal(jsonFile, &serviceAccount)
	if err != nil {
		fmt.Println("Error parsing service account file:", err)
		os.Exit(1)
	}

	projectId := serviceAccount.ProjectId

	switch basename {
	case "dns_add_google_cloud_dns":
		fmt.Println("dns_add_google_cloud_dns")
		editGoogleCloudDns("UPSERT", fqdn, challenge, projectId, serviceKeyAccountFile)
		waitAvailable(fqdn, challenge)
		break
	case "dns_remove_google_cloud_dns":
		fmt.Println("dns_remove_google_cloud_dns")
		editGoogleCloudDns("DELETE", fqdn, challenge, projectId, serviceKeyAccountFile)
		break
	default:
		fmt.Println("Unknown basename")
		os.Exit(1)
	}
}

func editGoogleCloudDns(action string, fqdn string, challenge string, projectId string, serviceKeyAccountFile string) {
	// Google Cloud DNSのクライアントを作成
	ctx := context.Background()
	dnsService, err := dns.NewService(ctx, option.WithCredentialsFile(serviceKeyAccountFile))
	if err != nil {
		fmt.Println("Error creating DNS service:", err)
		os.Exit(1)
	}

	zones, err := dnsService.ManagedZones.List(projectId).Do()
	if err != nil {
		fmt.Println("Error listing managed zones:", err)
		os.Exit(1)
	}

	sort.Slice(zones.ManagedZones, func(i, j int) bool {
		return len(zones.ManagedZones[i].DnsName) > len(zones.ManagedZones[i].DnsName)
	})

	var matchedZone string

	for _, zone := range zones.ManagedZones {
		dnsName := zone.DnsName
		match, _ := regexp.MatchString(dnsName[0:len(dnsName)-1], fqdn)

		if match {
			fmt.Println("Matched")
			fmt.Println("zone name: ", zone.Name)
			fmt.Println("zone dns name: ", dnsName)
			matchedZone = zone.Name
			break
		}
	}

	if matchedZone == "" {
		fmt.Println("No matching zone found for the given FQDN.")
		os.Exit(1)
	}

	// DNSレコードを編集
	recordSet := &dns.ResourceRecordSet{
		Name:    "_acme-challenge." + fqdn + ".",
		Type:    "TXT",
		Ttl:     300,
		Rrdatas: []string{challenge},
	}

	change := &dns.Change{
		Additions: []*dns.ResourceRecordSet{recordSet},
	}

	if action == "DELETE" {
		change.Additions = nil
		change.Deletions = []*dns.ResourceRecordSet{recordSet}
	}

	fmt.Println(matchedZone)
	fmt.Println(projectId)
	fmt.Println(action)

	_, err = dnsService.Changes.Create(projectId, matchedZone, change).Do()
	if err != nil {
		fmt.Println("Error editing DNS record:", err)
		os.Exit(1)
	}
}

func waitAvailable(fqdn string, challenge string) {
	for {
		texts, err := net.LookupTXT(fmt.Sprintf("_acme-challenge.%s", fqdn))
		if err == nil {
			for _, addr := range texts {
				fmt.Println(addr)
				if addr == fmt.Sprintf("%s", challenge) {
					fmt.Println("DNS is available")
					os.Exit(0)
				}
			}
			break
		} else {
			fmt.Println("Waiting for DNS to be available")
			fmt.Println(err)
		}
		time.Sleep(10 * time.Second)
	}
}
