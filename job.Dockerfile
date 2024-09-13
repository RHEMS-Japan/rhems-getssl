FROM alpine:3.20.3

RUN apk add --no-cache bind-tools jq unzip sudo curl bash openssl

WORKDIR /tmp/getssl

RUN curl --silent https://raw.githubusercontent.com/srvrco/getssl/latest/getssl > getssl ; chmod 700 getssl

WORKDIR /tmp/awscli

RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
RUN unzip awscliv2.zip
RUN sudo ./aws/install

WORKDIR /tmp/kubectl

RUN curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" \
      && mv kubectl /usr/local/bin/kubectl \
      && chmod +x /usr/local/bin/kubectl

RUN mkdir -p /var/www/html/.well-known/acme-challenge && chmod 777 /var/www/html/.well-known/acme-challenge
