#!/bin/bash

_domain=$1
_environment=$2

cd /root
mv /tmp/getssl/getssl /root/getssl
mv /tmp/create-cert /root/create-cert
cp /tmp/dns_edit_route53 /root/dns_add_route53
cp /tmp/dns_edit_route53 /root/dns_remove_route53
cp /tmp/dns_edit_google_cloud_dns /root/dns_add_google_cloud_dns
cp /tmp/dns_edit_google_cloud_dns /root/dns_remove_google_cloud_dns
mv /tmp/configmap/account-key-base.yml /root/account-key-base.yml
mv /tmp/configmap/acme-challenge-base.yml /root/acme-challenge-base.yml
mv /tmp/configmap/file-name-base.yml /root/file-name-base.yml
mv /tmp/configmap/secret-base.yml /root/secret-base.yml
mv /tmp/configmap/cert-secret-base.yml /root/cert-secret-base.yml
./getssl -c "${_domain}"
sed -i 's/SANS=/#SANS=/g' /root/.getssl/"${_domain}"/getssl.cfg
echo "ACL=('/var/www/html/.well-known/acme-challenge')" >> /root/.getssl/"${_domain}"/getssl.cfg
echo "USE_SINGLE_ACL='true'" >> /root/.getssl/"${_domain}"/getssl.cfg
echo "DOMAIN_CHAIN_LOCATION='.'" >> /root/.getssl/"${_domain}"/getssl.cfg

if [[ "${_environment}" == "production" ]]; then
  echo "production ca"
  echo "CA='https://acme-v02.api.letsencrypt.org'" >> /root/.getssl/"${_domain}"/getssl.cfg
else
  echo "staging ca"
  echo "CA='https://acme-staging-v02.api.letsencrypt.org'" >> /root/.getssl/"${_domain}"/getssl.cfg
fi

_configmap_account_key=$(kubectl get cm account-key -o json | jq -r '.data."account.key"');

if [[ "${_configmap_account_key}" == "__CONTENT__" ]] || [[ -z "${_configmap_account_key}" ]]; then
  echo "account.key is empty"
  cp account-key-base.yml account-key.yml
  ./getssl "${_domain}"
  while read -r line; do
    printf "    %s\n" "${line}" >> account-key.yml
  done < /root/.getssl/account.key
  kubectl apply -f account-key.yml -n "${POD_NAMESPACE}"
else
  echo "account.key is not empty"
  echo "${_configmap_account_key}" > /root/.getssl/account.key
fi
