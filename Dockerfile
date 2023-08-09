FROM golang:alpine as builder

WORKDIR /build
COPY . .
WORKDIR cmd/routedns
RUN GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build

FROM alpine:3.18.3
COPY --from=builder /build/cmd/routedns/routedns .
COPY cmd/routedns/example-config/simple-dot-proxy.toml config.toml
EXPOSE 53/tcp 53/udp
ENTRYPOINT ["/routedns"]
CMD ["config.toml"]
