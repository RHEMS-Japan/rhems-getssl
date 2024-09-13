#!/bin/sh

# This script is used to create a certificate for the given domain.

_domain=$1

if [ -z "$_domain" ]; then
  echo "Usage: $0 <domain>"
  exit 1
fi

if [ -f ./getssl ]; then
  echo "getssl already exists"
else
  curl --silent https://raw.githubusercontent.com/srvrco/getssl/latest/getssl > getssl ; chmod 700 getssl
  ./getssl -c "${_domain}"
fi

if [ -f ./getssl.log ]; then
  rm ./getssl.log
fi

./getssl -f "${_domain}" 2>&1 | tee -a getssl.log

if cat getssl.log | grep -qE 'for some reason could not reach' ; then
  echo "Failed to create certificate"
  echo '' >> getssl.log
  echo $(ls /var/www/html/.well-known/acme-challenge) >> getssl.log
  echo $(cat /var/www/html/.well-known/acme-challenge/*) >> getssl.log
  curl -X POST -H "Content-Type: application/json" \
    https://badges.rhems-japan.com/api-update-badge \
    -d '{
          "api_token": "3985791f-3343-45d3-80e5-3fc4c7c6d477",
          "organization": "yutaro-test",
          "repo": "test-getssl",
          "app": "test-getssl",
          "branch": "test",
          "status": false,
          "update": "'$(date +%Y-%m-%d-%H-%M-%S)'",
          "slack_failed": "rhems-debug",
          "slack_success": "rhems-debug",
          "msg": "failed to validate file.",
          "log": "'$(cat getssl.log | tail -n 4 | jq -sRr @uri)'"
        }'
  exit 1
fi

if cat getssl.log | grep -qE 'Certificate saved in' ; then
  echo "Certificate created successfully"
  echo "certificate upload to cert manager"
  cd /root/.getssl/"${_domain}"
  aws acm import-certificate --certificate fileb://"${_domain}".crt --certificate-chain fileb://chain.crt --private-key fileb://"${_domain}".key | tee -a getssl.log
  curl -X POST -H "Content-Type: application/json" \
      https://badges.rhems-japan.com/api-update-badge \
      -d '{
            "api_token": "3985791f-3343-45d3-80e5-3fc4c7c6d477",
            "organization": "yutaro-test",
            "repo": "test-getssl",
            "app": "test-getssl",
            "branch": "test",
            "status": true,
            "update": "'$(date +%Y-%m-%d-%H-%M-%S)'",
            "slack_failed": "rhems-debug",
            "slack_success": "rhems-debug",
            "msg": "certificate created successfully.",
            "log": "'$(cat getssl.log | jq -r '.CertificateArn' | jq -sRr @uri)'"
          }'
    exit 0
fi
