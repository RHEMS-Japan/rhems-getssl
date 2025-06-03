FROM golang:1.24.3-alpine3.21 AS create-cert
WORKDIR /tmp/create-cert
COPY ./create-cert/go.mod ./create-cert/go.sum ./
COPY ./create-cert/create-cert.go ./create-cert/check-remote-cert.go ./
RUN go mod download
RUN go build -ldflags="-w -s" -o ./create-cert ./create-cert.go ./check-remote-cert.go

FROM golang:1.24.3-alpine3.21 AS dns_edit_route53
WORKDIR /tmp/dns_edit_route53
COPY route53/go.mod route53/go.sum ./
COPY route53/dns_edit_route53.go ./
RUN go mod download
RUN go build -ldflags="-w -s" -o ./dns_edit_route53 ./dns_edit_route53.go

FROM golang:1.24.3-alpine3.21 AS go-server
WORKDIR /tmp/go-server
COPY go-server/go.mod ./
COPY go-server/server.go ./
RUN go mod download
RUN go build -ldflags="-w -s" -o ./server ./server.go

FROM golang:1.24.3-alpine3.21 AS delete-old-cert
WORKDIR /tmp/delete-old-cert
COPY delete-old-cert/go.mod delete-old-cert/go.sum ./
COPY delete-old-cert/check-remote-cert.go delete-old-cert/delete-old-cert.go ./
RUN go mod download
RUN go build -ldflags="-w -s" -o ./delete-old-cert ./delete-old-cert.go ./check-remote-cert.go

FROM alpine:3.21.3 AS kubectl
WORKDIR /tmp/kubectl
RUN apk add curl bash
COPY ./kubectl-install.sh /tmp/kubectl/kubectl-install.sh
RUN chmod +x kubectl-install.sh && /bin/bash kubectl-install.sh

FROM alpine:3.21.3

# Install necessary packages
RUN apk add --no-cache bind-tools jq unzip sudo curl bash openssl git

# Install getssl
WORKDIR /tmp/getssl
RUN curl --silent https://raw.githubusercontent.com/srvrco/getssl/latest/getssl > getssl ; chmod 700 getssl

# Create a directory for the acme-challenge
RUN mkdir -p /var/www/html/.well-known/acme-challenge && chmod 777 /var/www/html/.well-known/acme-challenge

COPY --from=create-cert /tmp/create-cert/create-cert /tmp/create-cert

COPY --from=dns_edit_route53 /tmp/dns_edit_route53/dns_edit_route53 /tmp/dns_edit_route53

COPY --from=delete-old-cert /tmp/delete-old-cert/delete-old-cert /root/delete-old-cert

COPY --from=go-server /tmp/go-server/server /root/server

COPY --from=kubectl /tmp/kubectl/kubectl /usr/local/bin/kubectl

COPY ./init.sh /tmp/init.sh
RUN chmod +x /tmp/init.sh

COPY ./account-key-base.yml /tmp/configmap/account-key-base.yml
COPY ./acme-challenge-base.yml /tmp/configmap/acme-challenge-base.yml
COPY ./file-name-base.yml /tmp/configmap/file-name-base.yml
COPY ./secret-base.yml /tmp/configmap/secret-base.yml
COPY ./cert-secret-base.yml /tmp/configmap/cert-secret-base.yml
