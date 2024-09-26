#!/bin/bash

_domain=$1

cd /root
mv /tmp/getssl/getssl /root/getssl
mv /tmp/create-cert /root/create-cert
./getssl -c "${_domain}"
sed -i 's/SANS=/#SANS=/g' /root/.getssl/"${_domain}"/getssl.cfg
echo "CA='https://acme-staging-v02.api.letsencrypt.org'" >> /root/.getssl/"${_domain}"/getssl.cfg
# echo "CA='https://acme-v02.api.letsencrypt.org'" >> /root/.getssl/"${_domain}"/getssl.cfg
echo "ACL=('/var/www/html/.well-known/acme-challenge')" >> /root/.getssl/"${_domain}"/getssl.cfg
echo "USE_SINGLE_ACL='true'" >> /root/.getssl/"${_domain}"/getssl.cfg

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



