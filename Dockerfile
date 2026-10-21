FROM golang:1.27.3-alpine3.24@sha256:f2c872bcee949b7be9c490efd02b48a8a2fbf947cdf533f1c58525ec9d8170fd

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
