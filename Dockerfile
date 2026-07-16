FROM golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2

RUN apk add git

USER nobody:nogroup

ENV CGO_ENABLED=0 GO111MODULE=on XDG_CACHE_HOME=/tmp/.cache

WORKDIR /go/src/github.com/sensiblecodeio/hookbot

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go install -v -buildvcs=false

EXPOSE 8080

ENTRYPOINT ["hookbot"]
