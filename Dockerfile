FROM nginx:1.27.1-bookworm

RUN apt update &&\
    apt install -y \
        host \
        jq  \
        unzip \
        sudo \
    && apt clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp/getssl

RUN curl --silent https://raw.githubusercontent.com/srvrco/getssl/latest/getssl > getssl ; chmod 700 getssl

WORKDIR /tmp/awscli

RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
RUN unzip awscliv2.zip
RUN sudo ./aws/install

ENTRYPOINT ["/bin/bash", "-c"]

CMD ["nginx", "-g", "daemon off;"]
