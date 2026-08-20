# syntax=docker/dockerfile:1.18

FROM golang:1.26.6-alpine AS build

RUN apk add --no-cache ca-certificates
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
ARG DPROXY_VERSION
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath -buildvcs=false \
    -ldflags="-buildid= -s -w -X main.version=${DPROXY_VERSION}" \
    -o /out/dproxy ./cmd/dproxy

FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=65532:65532 /out/dproxy /dproxy
COPY --chown=65532:65532 configs/server.container.toml /etc/dproxy/server.toml

USER 65532:65532
EXPOSE 8686
ENTRYPOINT ["/dproxy"]
CMD ["server", "--config", "/etc/dproxy/server.toml"]
