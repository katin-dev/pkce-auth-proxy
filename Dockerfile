FROM golang:1.14.1
WORKDIR /go/src/github.com/katin.dev/pkce-auth-proxy
COPY go.mod go.mod
COPY go.sum go.sum
COPY main.go main.go

EXPOSE 80
RUN go mod download
RUN go mod vendor
RUN go install

CMD ["pkce-auth-proxy"]