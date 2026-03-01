FROM golang:1.23-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -trimpath \
  -ldflags="-s -w -X main.version=${VERSION}" \
  -o /out/sops-cop .

FROM alpine:3.20

RUN addgroup -S app && adduser -S app -G app

WORKDIR /app
COPY --from=builder /out/sops-cop /usr/local/bin/sops-cop

USER app
ENTRYPOINT ["/usr/local/bin/sops-cop"]
CMD ["-target", "."]
