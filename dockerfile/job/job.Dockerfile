FROM alpine:3.20.3

# Install necessary packages
RUN apk add --no-cache bind-tools jq unzip sudo curl bash openssl aws-cli git py3-pip pwgen

# Install getssl
WORKDIR /tmp/getssl
RUN curl --silent https://raw.githubusercontent.com/srvrco/getssl/latest/getssl > getssl ; chmod 700 getssl

# Install kubectl
WORKDIR /tmp/kubectl
RUN curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" \
      && mv kubectl /usr/local/bin/kubectl \
      && chmod +x /usr/local/bin/kubectl

# Install tccli
WORKDIR /tmp/tccli
RUN sudo pip3 install --break-system-packages tccli-intl-en

# Create a directory for the acme-challenge
RUN mkdir -p /var/www/html/.well-known/acme-challenge && chmod 777 /var/www/html/.well-known/acme-challenge
