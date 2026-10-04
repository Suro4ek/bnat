FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o /bnat ./cmd/bnat

FROM alpine:3
RUN apk add --no-cache ca-certificates
COPY --from=build /bnat /usr/local/bin/bnat
# Server state (bnat.json, certificates) and agent config/host key.
ENV BNAT_DATA=/data BNAT_CONFIG_DIR=/config
ENTRYPOINT ["bnat"]
CMD ["server"]
