# syntax=docker/dockerfile:1

# ---------------------------------------------------------------- build stage
FROM golang:1.23-alpine AS build

# git lets the module proxy fall back to VCS checkouts if it ever needs to.
RUN apk add --no-cache git

WORKDIR /src

# Dependencies are copied first so the download layer stays cached while only
# application source changes. go.sum is optional (the glob tolerates its
# absence) so a fresh checkout builds either way.
COPY go.mod go.sum* ./
RUN go mod download all

COPY . .

ARG VERSION=docker

# CGO is disabled to produce a static binary, so the runtime image needs no Go
# toolchain or libc shims. -mod=mod lets the build record any missing go.sum
# entries rather than failing on a checkout where go.sum was never committed.
RUN CGO_ENABLED=0 GOOS=linux go build -mod=mod -trimpath \
        -ldflags="-s -w -X main.version=${VERSION}" \
        -o /out/cli-login ./cmd/cli-login

# Run the unit tests inside the image build so a broken build cannot be
# published. Tests needing a live database skip themselves unless
# TEST_DATABASE_URL is set, so this stays hermetic.
RUN go test ./...

# -------------------------------------------------------------- runtime stage
FROM alpine:3.20

# tzdata so TZ renders local timestamps in the user details block;
# ca-certificates is standard hygiene for any outbound TLS.
RUN apk add --no-cache ca-certificates tzdata \
    && adduser -D -u 10001 -h /home/app app

COPY --from=build /out/cli-login /usr/local/bin/cli-login

# Run unprivileged: nothing here needs root, and the state directory lives in
# the user's own home.
USER app
WORKDIR /home/app

# Session cache and shell history. Mounted as a volume in docker-compose so a
# session survives replacing the container.
ENV STATE_DIR=/home/app/.cli-login

ENTRYPOINT ["cli-login"]
