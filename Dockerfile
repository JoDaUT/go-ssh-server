FROM golang:1.24-alpine

RUN apk add make sudo libcap-setcap
# integration tests rely on this user
RUN adduser --disabled-password test

WORKDIR /go/src/