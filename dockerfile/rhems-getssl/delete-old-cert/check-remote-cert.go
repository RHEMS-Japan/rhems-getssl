package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/tencentcloud/tencentcloud-sdk-go-intl-en/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go-intl-en/tencentcloud/common/errors"
	"github.com/tencentcloud/tencentcloud-sdk-go-intl-en/tencentcloud/common/profile"
	ssl "github.com/tencentcloud/tencentcloud-sdk-go-intl-en/tencentcloud/ssl/v20191205"
	"os"
	"regexp"
	"strings"
	"time"
)

type TencentCertResponse struct {
	Response struct {
		Content     string `json:"Content"`
		ContentType string `json:"ContentType"`
		RequestId   string `json:"RequestId"`
	} `json:"Response"`
}

func isCertTimeInvalid(certNotAfter time.Time) bool {
	if time.Now().After(certNotAfter) {
		return true
	} else {
		return false
	}
}

func getAWSCertARNs() (*[]types.CertificateSummary, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Println(err.Error())
		return nil, err
	}

	client := acm.NewFromConfig(cfg)

	includes := types.Filters{
		KeyTypes: append(make([]types.KeyAlgorithm, 0), types.KeyAlgorithmRsa4096),
	}

	input := &acm.ListCertificatesInput{
		Includes: &includes,
	}

	output, err := client.ListCertificates(context.TODO(), input)
	if err != nil {
		fmt.Println(err.Error())
		return nil, err
	}

	certificates := output.CertificateSummaryList
	if output.NextToken != nil {
		input.NextToken = output.NextToken
		for output.NextToken != nil {
			output, err = client.ListCertificates(context.TODO(), input)
			if err != nil {
				fmt.Println(err.Error())
				return nil, err
			}
			certificates = append(certificates, output.CertificateSummaryList...)
		}
	}

	return &certificates, nil
}

func getTencentCertIds() (*[]*ssl.Certificates, error) {
	credential := common.NewCredential(os.Getenv("TENCENTCLOUD_SECRET_ID"), os.Getenv("TENCENTCLOUD_SECRET_KEY"))

	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "ssl.tencentcloudapi.com"

	client, _ := ssl.NewClient(credential, "", cpf)

	request := ssl.NewDescribeCertificatesRequest()

	response, err := client.DescribeCertificates(request)
	if _, ok := err.(*errors.TencentCloudSDKError); ok {
		fmt.Printf("An API error has returned: %s", err)
		return nil, err
	}
	if err != nil {
		fmt.Println(err.Error())
		return nil, err
	}

	certificates := response.Response.Certificates
	for *response.Response.TotalCount > uint64(len(certificates)) {
		request.Offset = common.Uint64Ptr(uint64(len(certificates)))
		response, err = client.DescribeCertificates(request)
		if _, ok := err.(*errors.TencentCloudSDKError); ok {
			fmt.Printf("An API error has returned: %s", err)
			return nil, err
		}
		if err != nil {
			fmt.Println(err.Error())
			return nil, err
		}
		certificates = append(certificates, response.Response.Certificates...)
	}
	return &certificates, nil
}

func checkTencentCert(certIds []string, domains []string) {
	for _, certId := range certIds {
		cert, err := getCertTencent(certId)
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		} else if cert == nil {
			continue
		}

		notAfter, sans, err := readCert(cert.Response.Content)
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}

		isMatch := false
		for _, subjectAltName := range sans {
			for _, domain := range domains {
				domainArray := strings.Split(domain, ".")
				sanArray := strings.Split(subjectAltName, ".")
				if len(domainArray) != len(sanArray) {
					continue
				}
				if domainArray[0] == "*" {
					nakedDomain := domainArray[1 : len(domainArray)-1]
					nakedSAN := sanArray[1 : len(sanArray)-1]
					fmt.Println(strings.Join(nakedDomain, "."))
					fmt.Println(strings.Join(nakedSAN, "."))
					if strings.Join(nakedDomain, ".") == strings.Join(nakedSAN, ".") {
						isMatch = true
					}
				} else {
					if subjectAltName == domain {
						isMatch = true
					}
				}
			}
		}

		if !isMatch {
			fmt.Println("Certificate is not under management")
			continue
		}

		if isCertTimeInvalid(notAfter) {
			fmt.Println("Certificate is invalid")
			response, err := deleteTencentCert(certId)
			if err != nil {
				fmt.Println(err.Error())
				os.Exit(1)
			}
			fmt.Println(response)
		} else {
			fmt.Println("Certificate is valid")
		}
	}
}

func checkAWSCert(certARNs []string, domains []string) {
	for _, certARN := range certARNs {
		cert, err := getCertAWS(certARN)
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}

		notAfter, sans, err := readCert(*cert.Certificate)
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}

		isMatch := false
		for _, subjectAltName := range sans {
			for _, domain := range domains {
				domainArray := strings.Split(domain, ".")
				sanArray := strings.Split(subjectAltName, ".")
				if len(domainArray) != len(sanArray) {
					continue
				}
				if domainArray[0] == "*" {
					nakedDomain := domainArray[1 : len(domainArray)-1]
					nakedSAN := sanArray[1 : len(sanArray)-1]
					fmt.Println(strings.Join(nakedDomain, "."))
					fmt.Println(strings.Join(nakedSAN, "."))
					if strings.Join(nakedDomain, ".") == strings.Join(nakedSAN, ".") {
						isMatch = true
					}
				} else {
					if subjectAltName == domain {
						isMatch = true
					}
				}
			}
		}

		if !isMatch {
			fmt.Println("Certificate is not under management")
			continue
		}

		if isCertTimeInvalid(notAfter) {
			fmt.Println("Certificate is invalid")
			response, err := deleteAWSCert(certARN)
			if err != nil {
				fmt.Println(err.Error())
				os.Exit(1)
			}
			fmt.Println(response)
		} else {
			fmt.Println("Certificate is valid")
		}
	}
}

func deleteTencentCert(certId string) (*ssl.DeleteCertificateResponse, error) {
	credential := common.NewCredential(os.Getenv("TENCENTCLOUD_SECRET_ID"), os.Getenv("TENCENTCLOUD_SECRET_KEY"))

	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "ssl.tencentcloudapi.com"

	client, _ := ssl.NewClient(credential, "", cpf)

	request := ssl.NewDeleteCertificateRequest()

	request.CertificateId = common.StringPtr(certId)

	response, err := client.DeleteCertificate(request)
	if _, ok := err.(*errors.TencentCloudSDKError); ok {
		fmt.Printf("An API error has returned: %s", err)
		return nil, err
	}
	if err != nil {
		fmt.Println(err.Error())
		return nil, err
	}

	return response, nil
}

func deleteAWSCert(certARN string) (*acm.DeleteCertificateOutput, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Println(err.Error())
		return nil, err
	}

	client := acm.NewFromConfig(cfg)

	input := &acm.DeleteCertificateInput{
		CertificateArn: &certARN,
	}

	output, err := client.DeleteCertificate(context.TODO(), input)
	if err != nil {
		fmt.Println(err.Error())
		return nil, err
	}

	return output, nil
}

func getCertTencent(id string) (*TencentCertResponse, error) {
	credential := common.NewCredential(os.Getenv("TENCENTCLOUD_SECRET_ID"), os.Getenv("TENCENTCLOUD_SECRET_KEY"))
	cpf := profile.NewClientProfile()
	cpf.HttpProfile.Endpoint = "ssl.tencentcloudapi.com"

	client, _ := ssl.NewClient(credential, "", cpf)

	request := ssl.NewDownloadCertificateRequest()

	request.CertificateId = common.StringPtr(id)

	response, err := client.DownloadCertificate(request)
	if _, ok := err.(*errors.TencentCloudSDKError); ok {
		pattern := `.*Code=FailedOperation.CertificateNotFound, Message=Certificate does not exist..*`
		match, _ := regexp.MatchString(pattern, err.Error())
		if match {
			fmt.Println("Certificate not found")
			return nil, nil
		} else {
			fmt.Printf("An API error has returned: %s", err)
			return nil, err
		}
	}

	var certResponse TencentCertResponse
	if err := json.Unmarshal([]byte(response.ToJsonString()), &certResponse); err != nil {
		fmt.Println(err.Error())
		return nil, err
	}

	decodeContent, err := b64.StdEncoding.DecodeString(certResponse.Response.Content)
	if err != nil {
		fmt.Println("Failed to decode content")
		fmt.Println(err.Error())
		return nil, err
	}

	certResponse.Response.Content = string(decodeContent)

	err = writeZipFile("cert.zip", []byte(certResponse.Response.Content))
	if err != nil {
		fmt.Println("Failed to write zip file")
		fmt.Println(err.Error())
		return nil, err
	}

	reader, err := zip.OpenReader("cert.zip")
	if err != nil {
		fmt.Println("Failed to read zip file")
		fmt.Println(err.Error())
		return nil, err
	}

	defer reader.Close()

	for _, file := range reader.File {
		rc, err := file.Open()
		if err != nil {
			fmt.Println("Failed to open file")
			fmt.Println(err.Error())
			return nil, err
		}
		pemRegExp := regexp.MustCompile(`\.pem$`)
		if pemRegExp.MatchString(file.Name) {
			contentReader, err := file.Open()
			if err != nil {
				fmt.Println("Failed to open raw file")
				fmt.Println(err.Error())
				return nil, err
			}

			buf := new(bytes.Buffer)
			_, err = buf.ReadFrom(contentReader)
			if err != nil {
				fmt.Println("Failed to read content")
				fmt.Println(err.Error())
				return nil, err
			}

			certResponse.Response.Content = buf.String()

			_ = contentReader.Close()
		}
		_ = rc.Close()
	}

	return &certResponse, nil
}

func getCertAWS(arn string) (*acm.GetCertificateOutput, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		fmt.Println(err.Error())
		return nil, err
	}

	client := acm.NewFromConfig(cfg)

	input := &acm.GetCertificateInput{
		CertificateArn: &arn,
	}

	output, err := client.GetCertificate(context.TODO(), input)
	if err != nil {
		fmt.Println(err.Error())
		return nil, err
	}

	return output, nil
}

func readCert(cert string) (time.Time, []string, error) {
	if cert == "" {
		fmt.Println("No certificate found")
		return time.Time{}, []string{}, fmt.Errorf("no certificate found")
	}

	block, _ := pem.Decode([]byte(cert))
	if block == nil {
		fmt.Println("Failed to parse certificate")
		return time.Time{}, []string{}, fmt.Errorf("failed to parse certificate")
	}

	parsedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Println("Failed to parse certificate")
		fmt.Println(err)
		return time.Time{}, []string{}, err
	}

	fmt.Println("Not After: " + parsedCert.NotAfter.String())
	fmt.Println("Not Before: " + parsedCert.NotBefore.String())
	fmt.Println("Subject: " + parsedCert.Subject.String())
	fmt.Println("Subject Alternate Names: " + parsedCert.DNSNames[0])

	return parsedCert.NotAfter, parsedCert.DNSNames, nil
}

func writeZipFile(name string, contents []byte) error {
	file, err := os.Create(name)
	if err != nil {
		fmt.Println("Failed to create file")
		fmt.Println(err.Error())
		return err
	}
	defer file.Close()

	_, err = file.Write(contents)
	if err != nil {
		fmt.Println("Failed to write to file")
		fmt.Println(err.Error())
		return err
	}

	return nil
}
