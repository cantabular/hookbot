FROM golang:1.27.4-alpine3.24@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280

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
