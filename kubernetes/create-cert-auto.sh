#!/bin/bash

# This script is used to create a certificate for the given domain.

_domain=$1
_namespace=$2

if [ -z "$_domain" ]; then
  echo "Usage: $0 <domain> <namespace>"
  exit 1
fi

if [ -z "$_namespace" ]; then
  _namespace=${POD_NAMESPACE}
  if [ -z "$_namespace" ]; then
    echo "Usage: $0 <domain> <namespace>"
    exit 1
  fi
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

if cat getssl.log | grep -qE 'Verification completed, obtaining certificate'; then
  echo "Certificate created successfully"
  echo "certificate upload to cert manager"
  cd /root/.getssl/"${_domain}"
  _log=""
  if [ "${CLOUD}" == "aws" ]; then
    echo "aws"
    aws acm import-certificate --certificate fileb://"${_domain}".crt --certificate-chain fileb://chain.crt --private-key fileb://"${_domain}".key | tee -a getssl.log
    _log=$(cat getssl.log | jq -r '.CertificateArn' | jq -sRr @uri)
  elif [ "${CLOUD}" == "tencent" ]; then
    echo "tencent"
    _alias="cert_$(date '+%Y%m%d%H%M%S')"
    _private_key=$(cat "${_domain}".key)
    _public_key=$(cat "${_domain}".crt)
    tccli ssl UploadCertificate --CertificatePublicKey "${_public_key}" --CertificatePrivateKey "${_private_key}" --CertificateType SVR --output json --Alias "${_alias}" | tee -a getssl.log
    _log=$(cat getssl.log | jq -r '.CertificateId' | jq -sRr @uri)

    _cert_secret_name=$(kubectl get secrets -n "${POD_NAMESPACE}" -o json | jq -r '.items[].metadata.name' | grep -e '^certificate-[a-z,0-9]*')
    kubectl patch secret -n "${POD_NAMESPACE}" "${_cert_secret_name}" -p '{"data":{"qcloud_cert_id":"'"${_log}"'"}}'

    _log="update qcloud_cert_id in secret. Namespace: ${POD_NAMESPACE}, secret name: ${_cert_secret_name}"
  fi
  curl -X POST -H "Content-Type: application/json" \
        https://badges.rhems-japan.com/api-update-badge \
        -d '{
              "api_token": "'"${API_TOKEN}"'",
              "organization": "'"${ORGANIZATION}"'",
              "repo": "'"${REPO}"'",
              "app": "'"${APP}"'",
              "branch": "'"${BRANCH}"'",
              "status": true,
              "update": "'$(date +%Y-%m-%d-%H-%M-%S)'",
              "cronjob": "'"${CRON}"'",
              "grace_time": '"${GRACE_TIME}"',
              "slack_failed": "'"${SLACK_FAILED}"'",
              "slack_success": "'"${SLACK_SUCCESS}"'",
              "msg": "certificate created successfully.",
              "log": "'"${_log}"'"
            }'
  exit 0
fi

_file_name=""
_file_content=""
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

  kubectl rollout restart deployment rhems-getssl-go -n "${_namespace}"
done

count=0

while [ ${count} -lt 10 ]; do
  sleep 10
  count=$((count + 1))
  _str=$(curl -s -X GET http://"${_domain}"/.well-known/acme-challenge/"${_file_name}")
  if [ "${_str}" == "${_file_content}" ]; then
    echo "file founded"
    break
  else
    echo "file not found"
    echo "count: ${count}"
  fi
done

./getssl -f "${_domain}" 2>&1 | tee -a getssl.log

# cronjobにした場合下記
if cat getssl.log | grep -qE 'for some reason could not reach' ; then
  echo "Failed to create certificate"
  echo '' >> getssl.log
  echo $(ls /var/www/html/.well-known/acme-challenge) >> getssl.log
  echo $(cat /var/www/html/.well-known/acme-challenge/*) >> getssl.log
  curl -X POST -H "Content-Type: application/json" \
    https://badges.rhems-japan.com/api-update-badge \
    -d '{
          "api_token": "'"${API_TOKEN}"'",
          "organization": "'"${ORGANIZATION}"'",
          "repo": "'"${REPO}"'",
          "app": "'"${APP}"'",
          "branch": "'"${BRANCH}"'",
          "status": false,
          "update": "'$(date +%Y-%m-%d-%H-%M-%S)'",
          "update": "'$(date +%Y-%m-%d-%H-%M-%S)'",
          "cronjob": "'"${CRON}"'",
          "grace_time": '"${GRACE_TIME}"',
          "slack_failed": "'"${SLACK_FAILED}"'",
          "slack_success": "'"${SLACK_SUCCESS}"'",
          "msg": "failed to validate file.",
          "log": "'$(cat getssl.log | tail -n 4 | jq -sRr @uri)'"
        }'
  exit 1
fi

if cat getssl.log | grep -qE 'Certificate saved in' ; then
  echo "Certificate created successfully"
  echo "certificate upload to cert manager"
  cd /root/.getssl/"${_domain}"
  _log=""
  if [ "${CLOUD}" == "aws" ]; then
    echo "aws"
    aws acm import-certificate --certificate fileb://"${_domain}".crt --certificate-chain fileb://chain.crt --private-key fileb://"${_domain}".key | tee -a getssl.log
    kubectl patch ingress -n "${POD_NAMESPACE}" rhems-getssl-ingress -p "{\"metadata\":{\"annotations\":{\"alb.ingress.kubernetes.io/certificate-arn\":\"$(cat getssl.log | jq -r '.CertificateArn')\"}}}"
    _log=$(cat getssl.log | jq -r '.CertificateArn' | jq -sRr @uri)
  elif [ "${CLOUD}" == "tencent" ]; then
    echo "tencent"
    _alias="cert_$(date '+%Y%m%d%H%M%S')"
    _private_key=$(cat "${_domain}".key)
    _public_key=$(cat "${_domain}".crt)
    tccli ssl UploadCertificate --CertificatePublicKey "${_public_key}" --CertificatePrivateKey "${_private_key}" --CertificateType SVR --output json --Alias "${_alias}" | tee -a getssl.log
    _log=$(cat getssl.log | jq -r '.CertificateId' | jq -sRr @uri)

    _cert_secret_name=$(kubectl get secrets -n "${POD_NAMESPACE}" -o json | jq -r '.items[].metadata.name' | grep -e '^certificate-[a-z,0-9]*')
    kubectl patch secret -n "${POD_NAMESPACE}" "${_cert_secret_name}" -p '{"data":{"qcloud_cert_id":"'"${_log}"'"}}'

    _log="update qcloud_cert_id in secret. Namespace: ${POD_NAMESPACE}, secret name: ${_cert_secret_name}"
  fi
  curl -X POST -H "Content-Type: application/json" \
      https://badges.rhems-japan.com/api-update-badge \
      -d '{
            "api_token": "'"${API_TOKEN}"'",
            "organization": "'"${ORGANIZATION}"'",
            "repo": "'"${REPO}"'",
            "app": "'"${APP}"'",
            "branch": "'"${BRANCH}"'",
            "status": true,
            "update": "'$(date +%Y-%m-%d-%H-%M-%S)'",
            "cronjob": "'"${CRON}"'",
            "grace_time": '"${GRACE_TIME}"',
            "slack_failed": "'"${SLACK_FAILED}"'",
            "slack_success": "'"${SLACK_SUCCESS}"'",
            "msg": "certificate created successfully.",
            "log": "'"${_log}"'"
          }'
  exit 0
fi

#if cat getssl.log | grep -qE 'for some reason could not reach' ; then
#  echo "Failed to create certificate"
#  echo '' >> getssl.log
#  echo $(ls /var/www/html/.well-known/acme-challenge) >> getssl.log
#  echo $(cat /var/www/html/.well-known/acme-challenge/*) >> getssl.log
#  curl -X POST -H "Content-Type: application/json" \
#    https://badges.rhems-japan.com/api-update-badge \
#    -d '{
#          "api_token": "3985791f-3343-45d3-80e5-3fc4c7c6d477",
#          "organization": "yutaro-test",
#          "repo": "test-getssl",
#          "app": "test-getssl",
#          "branch": "test",
#          "status": false,
#          "update": "'$(date +%Y-%m-%d-%H-%M-%S)'",
#          "slack_failed": "rhems-debug",
#          "slack_success": "rhems-debug",
#          "msg": "failed to validate file.",
#          "log": "'$(cat getssl.log | tail -n 4 | jq -sRr @uri)'"
#        }'
#  exit 1
#fi
#
#if cat getssl.log | grep -qE 'Certificate saved in' ; then
#  echo "Certificate created successfully"
#  echo "certificate upload to cert manager"
#  cd /root/.getssl/"${_domain}"
#  _log=""
#  if [ "${CLOUD}" == "aws" ]; then
#    echo "aws"
#    aws acm import-certificate --certificate fileb://"${_domain}".crt --certificate-chain fileb://chain.crt --private-key fileb://"${_domain}".key | tee -a getssl.log
#    _log=$(cat getssl.log | jq -r '.CertificateArn' | jq -sRr @uri)
#  elif [ "${CLOUD}" == "tencent" ]; then
#    echo "tencent"
#    _alias="cert_$(date '+%Y%m%d%H%M%S')"
#    _private_key=$(cat "${_domain}".key)
#    _public_key=$(cat "${_domain}".crt)
#    tccli ssl UploadCertificate --CertificatePublicKey "${_public_key}" --CertificatePrivateKey "${_private_key}" --CertificateType SVR --output json --Alias "${_alias}" | tee -a getssl.log
#    _log=$(cat getssl.log | jq -r '.CertificateId' | jq -sRr @uri)
#
#    _cert_secret_name=$(kubectl get secrets -n "${POD_NAMESPACE}" -o json | jq -r '.items[].metadata.name' | grep -e '^certificate-[a-z,0-9]*')
#    kubectl patch secret -n "${POD_NAMESPACE}" "${_cert_secret_name}" -p '{"data":{"qcloud_cert_id":"'"${_log}"'"}}'
#
#    _log="update qcloud_cert_id in secret. Namespace: ${POD_NAMESPACE}, secret name: ${_cert_secret_name}"
#  fi
#  curl -X POST -H "Content-Type: application/json" \
#      https://badges.rhems-japan.com/api-update-badge \
#      -d '{
#            "api_token": "3985791f-3343-45d3-80e5-3fc4c7c6d477",
#            "organization": "yutaro-test",
#            "repo": "test-getssl",
#            "app": "test-getssl",
#            "branch": "test",
#            "status": true,
#            "update": "'$(date +%Y-%m-%d-%H-%M-%S)'",
#            "slack_failed": "rhems-debug",
#            "slack_success": "rhems-debug",
#            "msg": "certificate created successfully.",
#            "log": "'"${_log}"'"
#          }'
#  exit 0
#fi
