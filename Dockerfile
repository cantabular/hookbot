FROM golang:1.26.4-alpine@sha256:7a3e50096189ad57c9f9f865e7e4aa8585ed1585248513dc5cda498e2f41812c

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
