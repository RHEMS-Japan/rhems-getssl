#!/bin/bash

_domain=$1

cd /root
mv /tmp/getssl/getssl /root/getssl
./getssl -c "${_domain}"
sed -i 's/SANS=/#SANS=/g' /root/.getssl/"${_domain}"/getssl.cfg
echo "CA='https://acme-staging-v02.api.letsencrypt.org'" >> /root/.getssl/"${_domain}"/getssl.cfg
echo "ACL=('/var/www/html/.well-known/acme-challenge')" >> /root/.getssl/"${_domain}"/getssl.cfg
echo "USE_SINGLE_ACL='true'" >> /root/.getssl/"${_domain}"/getssl.cfg
