FROM golang:alpine AS builder
RUN apk add --no-cache git gcc libc-dev
WORKDIR /go/src/github.com/meni2029/sensu-go_exporter
ENV GO111MODULE=on
COPY go.mod .
COPY go.sum .
RUN go mod download

COPY sensu-go_exporter.go .
RUN go install .

FROM  golang:alpine
LABEL maintainer="github.com/meni2029"

COPY --from=builder /go/bin/sensu-go_exporter /bin/sensu-go_exporter

EXPOSE      9104
ENTRYPOINT  [ "/bin/sensu-go_exporter" ]
