FROM golang:1.23.1-alpine3.19 as create-cert
WORKDIR /tmp/create-cert
COPY go.mod go.sum ./
COPY create-cert.go ./
RUN go mod download
RUN go build -ldflags="-w -s" -o ./create-cert ./create-cert.go

FROM golang:1.23.1-alpine3.19 as dns_edit_route53
WORKDIR /tmp/dns_edit_route53
COPY route53/go.mod route53/go.sum ./
COPY route53/dns_edit_route53.go ./
RUN go mod download
RUN go build -ldflags="-w -s" -o ./dns_edit_route53 ./dns_edit_route53.go

FROM golang:1.23.1-alpine3.19 as go-server
WORKDIR /tmp/go-server
COPY go-server/go.mod ./
COPY go-server/server.go ./
RUN go mod download
RUN go build -ldflags="-w -s" -o ./server ./server.go

FROM alpine:3.20.3

# Install necessary packages
#RUN apk add --no-cache bind-tools jq unzip sudo curl bash openssl aws-cli git py3-pip pwgen
RUN apk add --no-cache bind-tools jq unzip sudo curl bash openssl git

# Install getssl
WORKDIR /tmp/getssl
RUN curl --silent https://raw.githubusercontent.com/srvrco/getssl/latest/getssl > getssl ; chmod 700 getssl

# Install kubectl
WORKDIR /tmp/kubectl
RUN curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" \
      && mv kubectl /usr/local/bin/kubectl \
      && chmod +x /usr/local/bin/kubectl

## Install tccli
#WORKDIR /tmp/tccli
#RUN sudo pip3 install --break-system-packages tccli-intl-en

# Create a directory for the acme-challenge
RUN mkdir -p /var/www/html/.well-known/acme-challenge && chmod 777 /var/www/html/.well-known/acme-challenge

COPY --from=create-cert /tmp/create-cert/create-cert /tmp/create-cert

COPY --from=dns_edit_route53 /tmp/dns_edit_route53/dns_edit_route53 /tmp/dns_edit_route53

COPY --from=go-server /tmp/go-server/server /root/server

COPY ./init.sh /tmp/init.sh
RUN chmod +x /tmp/init.sh

COPY ./account-key-base.yml /tmp/configmap/account-key-base.yml
COPY ./acme-challenge-base.yml /tmp/configmap/acme-challenge-base.yml
COPY ./file-name-base.yml /tmp/configmap/file-name-base.yml
COPY ./secret-base.yml /tmp/configmap/secret-base.yml
RUN chmod 777 /tmp/configmap/account-key-base.yml
RUN chmod 777 /tmp/configmap/acme-challenge-base.yml
RUN chmod 777 /tmp/configmap/file-name-base.yml
