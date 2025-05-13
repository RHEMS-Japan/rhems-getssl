package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"
)

var remain []string
var updateBeforeDay int

func init() {
	flag.IntVar(&updateBeforeDay, "update-before-day", 3, "Update before date. default '-update-before-day 3'")
	flag.Parse()

	remain = make([]string, 0, len(os.Args[1:]))
	args := os.Args[1:]

	for len(args) > 0 {
		err := flag.CommandLine.Parse(args)
		if err != nil {
			fmt.Println("Error:", err)
			os.Exit(1)
		}

		if flag.NArg() == 0 {
			break
		}

		args, remain = flag.Args()[1:], append(remain, flag.Args()[0])
	}
}

func main() {
	if len(remain) == 0 {
		fmt.Println("Use: check-cert url [options]")
		os.Exit(1)
	}

	for _, url := range remain {
		checkCertValidation(url)
	}

	os.Exit(0)
}

func checkCertValidation(url string) {
	res, err := http.Get("https://" + url)

	if err != nil {
		fmt.Println("cert validation error: ", err)
		os.Exit(1)
	}

	expireTime := res.TLS.PeerCertificates[0].NotAfter
	expireJSTTime := expireTime.In(time.FixedZone("Asia/Tokyo", 9*60*60))
	expireDate := fmt.Sprintf("%s UTC", expireTime.Format("2006-01-02 15:04:05"))
	expireJSTDate := fmt.Sprintf("%s JST", expireJSTTime.Format("2006-01-02 15:04:05"))

	fmt.Println("Domain: ", url)
	fmt.Println("Expire Date: ", expireDate)
	fmt.Println("Expire JST Date: ", expireJSTDate)
	fmt.Println("Update Before Day: ", updateBeforeDay)
	fmt.Println("しきい値: ", expireTime.Add(-24*time.Duration(updateBeforeDay)*time.Hour))
	fmt.Println("しきい値 JST: ", expireJSTTime.Add(-24*time.Duration(updateBeforeDay)*time.Hour))
	fmt.Println("Cert Time Valid: ", isCertTimeValid(expireTime))
	fmt.Println("")
}

func isCertTimeValid(certNotAfter time.Time) bool {
	if time.Now().After(certNotAfter.Add(-24 * time.Duration(updateBeforeDay) * time.Hour)) {
		return false
	} else {
		return true
	}
}
