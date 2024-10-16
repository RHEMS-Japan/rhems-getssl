package main

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"os"
	"path/filepath"
	"regexp"
	"sort"
)

var basename string
var fqdn string
var challenge string

func main() {
	basename = filepath.Base(os.Args[0])
	fqdn = os.Args[1]
	challenge = os.Args[2]

	switch basename {
	case "dns_add_route53":
		fmt.Println("dns_add_route53")
		edit_route53("UPSERT", fqdn, challenge)
		break
	case "dns_remove_route53":
		fmt.Println("dns_remove_route53")
		edit_route53("DELETE", fqdn, challenge)
		break
	default:
		fmt.Println("Unknown basename")
		os.Exit(1)
	}
}

func edit_route53(action string, fqdn string, challenge string) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Println("unable to load SDK config, ", err)
		os.Exit(1)
	}
	route53Client := route53.NewFromConfig(cfg)
	zones, err := route53Client.ListHostedZones(context.TODO(), &route53.ListHostedZonesInput{})
	if err != nil {
		fmt.Println("unable to list hosted zones, ", err)
		os.Exit(1)
	}

	sort.Slice(zones.HostedZones, func(i, j int) bool {
		return len(*zones.HostedZones[i].Name) > len(*zones.HostedZones[j].Name)
	})

	var matchedZoneId string
	for _, zone := range zones.HostedZones {
		name := *zone.Name
		match, _ := regexp.MatchString(name[0:len(name)-1], fqdn)

		if match {
			fmt.Println("Matched")
			fmt.Println("zone id: ", filepath.Base(*zone.Id))
			fmt.Println("zone name: ", name)
			matchedZoneId = filepath.Base(*zone.Id)
			break
		}
	}

	if matchedZoneId == "" {
		fmt.Println("No matched zone")
		os.Exit(1)
	}

	challengeFqdn := fmt.Sprintf("\"_acme-challenge.%s\"", fqdn)
	fmt.Println("challengeFqdn: ", challengeFqdn)
	value := fmt.Sprintf("\"%s\"", challenge)
	fmt.Println("value: ", value)
	comment := "getssl/Letsencrypt verification"
	var ttl int64 = 300
	resourceRecord := types.ResourceRecord{
		Value: &value,
	}
	resourceRecordSet := types.ResourceRecordSet{
		Name: &challengeFqdn,
		Type: "TXT",
		TTL:  &ttl,
		ResourceRecords: []types.ResourceRecord{
			resourceRecord,
		},
	}
	change := types.Change{
		Action:            types.ChangeAction(action),
		ResourceRecordSet: &resourceRecordSet,
	}
	changes := []types.Change{
		change,
	}
	changeBatch := types.ChangeBatch{
		Comment: &comment,
		Changes: changes,
	}

	createRecordInput := &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: &matchedZoneId,
		ChangeBatch:  &changeBatch,
	}

	_, err = route53Client.ChangeResourceRecordSets(context.TODO(), createRecordInput)
	if err != nil {
		fmt.Println("unable to create record, ", err)
		os.Exit(1)
	}
}
