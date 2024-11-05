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
	"github.com/tencentcloud/tencentcloud-sdk-go-intl-en/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go-intl-en/tencentcloud/common/errors"
	"github.com/tencentcloud/tencentcloud-sdk-go-intl-en/tencentcloud/common/profile"
	ssl "github.com/tencentcloud/tencentcloud-sdk-go-intl-en/tencentcloud/ssl/v20191205"
	"os"
	"regexp"
)

type TencentCertResponse struct {
	Response struct {
		Content     string `json:"Content"`
		ContentType string `json:"ContentType"`
		RequestId   string `json:"RequestId"`
	} `json:"Response"`
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
		fmt.Printf("An API error has returned: %s", err)
		return nil, err
	}
	if err != nil {
		fmt.Println(err.Error())
		return nil, err
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

func readCert(cert string) error {
	if cert == "" {
		fmt.Println("No certificate found")
		return fmt.Errorf("no certificate found")
	}

	block, _ := pem.Decode([]byte(cert))
	if block == nil {
		fmt.Println("Failed to parse certificate")
		return fmt.Errorf("failed to parse certificate")
	}

	parsedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Println("Failed to parse certificate")
		fmt.Println(err)
		return err
	}

	fmt.Println("Not After: " + parsedCert.NotAfter.String())
	fmt.Println("Not Before: " + parsedCert.NotBefore.String())

	return nil
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
