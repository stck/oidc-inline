FROM golang:1.26.2-alpine3.23 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/oidc-inline main.go

FROM ghcr.io/11notes/netbird-client:0.70
COPY --from=build /out/oidc-inline /etc/oidc-inline/browser
ENV BROWSER=/etc/oidc-inline/browser
