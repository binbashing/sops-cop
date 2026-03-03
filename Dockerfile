FROM alpine:3

WORKDIR /app

ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN apk add --no-cache ca-certificates curl && \
  case "${TARGETARCH}" in amd64|arm64) ;; *) echo "unsupported arch: ${TARGETARCH}"; exit 1 ;; esac && \
  BINARY_NAME="sops-cop_${VERSION}_${TARGETOS}_${TARGETARCH}" && \
  URL="https://github.com/binbashing/sops-cop/releases/download/${VERSION}/${BINARY_NAME}" && \
  curl --fail --silent --show-error --location \
    --retry 8 --retry-delay 5 --retry-connrefused \
    "${URL}" --output /usr/local/bin/sops-cop && \
  chmod +x /usr/local/bin/sops-cop

RUN addgroup -S app && adduser -S app -G app

USER app
ENTRYPOINT ["/usr/local/bin/sops-cop"]
CMD ["-target", "."]
