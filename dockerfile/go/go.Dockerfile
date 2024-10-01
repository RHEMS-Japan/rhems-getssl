FROM golang:1.23.1-alpine3.19 as build-go-server

RUN mkdir -p /root

WORKDIR /root

# build the server
COPY server.go /root/server.go
COPY go.mod /root/go.mod
RUN go mod download
RUN go build -ldflags="-s -w" -o /root/server /root/server.go

FROM alpine:3.20.3

RUN mkdir -p /root

WORKDIR /root

COPY --from=build-go-server /root/server /root/server
