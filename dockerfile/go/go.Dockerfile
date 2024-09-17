FROM golang:1.23.1-alpine3.19

RUN mkdir -p /root

WORKDIR /root

# build the server
COPY server.go /root/server.go
COPY go.mod /root/go.mod
RUN go mod download
RUN go build -o /root/server /root/server.go

