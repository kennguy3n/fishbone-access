# Multi-stage build for the ShieldNet Access Go binaries. A single image holds
# the four deployable binaries (ztna-api, access-connector-worker,
# access-workflow-engine, pam-gateway); each compose/Helm service selects one
# via its command. Alpine (not distroless) is used for the final stage so a
# shell + wget are available for compose healthchecks on the single-server tier.
FROM golang:1.25-alpine AS build
WORKDIR /src

# Cache module downloads.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ztna-api ./cmd/ztna-api && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/access-connector-worker ./cmd/access-connector-worker && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/access-workflow-engine ./cmd/access-workflow-engine && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/pam-gateway ./cmd/pam-gateway

FROM alpine:3.20
RUN apk add --no-cache ca-certificates wget && adduser -D -u 10001 shieldnet
COPY --from=build /out/ztna-api /usr/local/bin/ztna-api
COPY --from=build /out/access-connector-worker /usr/local/bin/access-connector-worker
COPY --from=build /out/access-workflow-engine /usr/local/bin/access-workflow-engine
COPY --from=build /out/pam-gateway /usr/local/bin/pam-gateway
USER shieldnet
EXPOSE 8080
# Default to the API; compose/Helm override `command` for the worker and gateway.
ENTRYPOINT ["ztna-api"]
