#!/bin/sh

# This script is used to create a certificate for the given domain.

_domain=$1
_namespace=$2

if [ -z "$_domain" ]; then
  echo "Usage: $0 <domain> <namespace>"
  exit 1
fi

if [ -z "$_namespace" ]; then
  echo "Usage: $0 <domain> <namespace>"
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

./getssl -f "${_domain}" 2>&1

for file in $(find /var/www/html/.well-known/acme-challenge/ -maxdepth 1 -type f); do
  echo "=== file ==="
  echo "${file}"
  cat "${file}"

  _file_name=$(basename "${file}")
  _file_content=$(cat "${file}")

  cp acme-challenge-base.yml acme-challenge.yml
  cp file-name-base.yml file-name.yml

  sed "s/__FILE_NAME__/$_file_name/g" -i acme-challenge.yml
  sed "s/__CONTENT__/${_file_content}/g" -i acme-challenge.yml
  sed "s/__FILE_NAME__/${_file_name}/g" -i file-name.yml

  kubectl delete configmap acme-challenge -n "${_namespace}"
  kubectl delete configmap file-name -n "${_namespace}"
  kubectl apply -f acme-challenge.yml -n "${_namespace}"
  kubectl apply -f file-name.yml -n "${_namespace}"

  kubectl rollout restart deployment test-getssl-go -n "${_namespace}"
done

sleep 180

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
