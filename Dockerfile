FROM --platform=$BUILDPLATFORM golang:1-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
  -trimpath \
  -ldflags="-s -w -X main.version=${VERSION}" \
  -o /out/sops-cop .

FROM alpine:3

RUN addgroup -S app && adduser -S app -G app

WORKDIR /app
COPY --from=builder /out/sops-cop /usr/local/bin/sops-cop

USER app
ENTRYPOINT ["/usr/local/bin/sops-cop"]
CMD ["-target", "."]
