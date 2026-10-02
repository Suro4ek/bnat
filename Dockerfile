FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /bnat ./cmd/bnat

FROM alpine:3
RUN apk add --no-cache ca-certificates
COPY --from=build /bnat /usr/local/bin/bnat
VOLUME /data
ENV BNAT_DATA=/data
ENTRYPOINT ["bnat", "server"]
