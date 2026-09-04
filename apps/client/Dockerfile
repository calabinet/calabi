# syntax=docker/dockerfile:1.7
#
# Dockerfile for the `calabi` client CLI — published as the public image
# advertised on the download page (`docker run --rm -it calabinet/calabi:latest
# http 8080`).
#
# Build from the REPO ROOT (the client references pkg/* via go.work replace
# directives, so the build context must contain apps/ + pkg/ + go.work):
#
#   docker build -f apps/client/Dockerfile -t calabinet/calabi:latest .
#
# Multi-arch (Docker Hub manifest list):
#   docker buildx build -f apps/client/Dockerfile \
#       --platform linux/amd64,linux/arm64 -t calabinet/calabi:1.1.0 .
#
# EDGE CA: the image bakes whatever is currently at
#   apps/client/internal/transport/certs/edge-ca.pem   (go:embed)
# The repo commits the DEV edge CA there. For a real published release, swap
# the PRODUCTION cert-svc edge-CA root in first — use
# scripts/build-release-image.sh, which mirrors scripts/build-release-client.sh
# (swap prod CA -> build -> verify no dev marker -> restore the dev cert).

# ============================================================================
# Stage 1 - builder
# ============================================================================
# --platform=$BUILDPLATFORM pins the builder stage to the HOST arch so Go
# cross-compiles via the GOOS/GOARCH below — which is what the TARGETOS/TARGETARCH
# lines already assume. Without it, buildx pulls the TARGET-arch golang image and
# runs the ENTIRE Go compile under QEMU for every non-native platform: same
# output, many times slower. Only the runtime stage's small `apk add` still needs
# emulation (so `tonistiigi/binfmt --install arm64` is still a prerequisite for
# the multi-arch build — and note those handlers live in the Docker VM's
# binfmt_misc and do NOT survive a Docker Desktop restart).
FROM --platform=$BUILDPLATFORM golang:1.25-bookworm AS builder
ARG VERSION=dev
# DEFAULT_BFF_CONSOLE bakes the compile-time control-plane endpoint (main.
# defaultBFFConsole). Defaults to the dev address so a plain `docker build`
# behaves like a plain `go build`; a published release passes the prod URL
# (scripts/build-release-image.sh sets BFF_CONSOLE=https://api.calabi.net),
# mirroring scripts/package-release-client.sh for the archives. A runtime
# CALABI_BFF_CONSOLE still overrides it.
ARG DEFAULT_BFF_CONSOLE=http://127.0.0.1:8002
# DEFAULT_CONSOLE_WEB bakes the browser-facing console origin (main.
# defaultConsoleWeb) the client's login page links to for registration. Separate
# from DEFAULT_BFF_CONSOLE on purpose: that's the API host (api.calabi.net), this
# is the SPA host (console.calabi.net) — one can't be derived from the other.
# Same dev default as a plain `go build`; a published release passes the prod URL
# (scripts/build-release-image.sh sets CONSOLE_WEB=https://console.calabi.net),
# mirroring scripts/package-release-client.sh for the archives. A runtime
# CALABI_CONSOLE_WEB still overrides it.
ARG DEFAULT_CONSOLE_WEB=http://127.0.0.1:5173
ARG GOPROXY=https://goproxy.cn,direct
# TARGETOS/TARGETARCH are auto-populated by BuildKit (native build) and by
# buildx (per --platform), so the same Dockerfile cross-builds for the manifest.
ARG TARGETOS
ARG TARGETARCH
ENV CGO_ENABLED=0 \
    GOOS=${TARGETOS} \
    GOARCH=${TARGETARCH} \
    GOFLAGS=-trimpath \
    GOPROXY=${GOPROXY}

WORKDIR /src

# Copy the module graph first so dependency download is layer-cached across
# code-only changes. apps/ + pkg/ ship together because the client references
# pkg/* via local replace directives; go.work + go.work.sum carry the
# transitive-dep checksums (see the note in .dockerignore).
COPY apps/         apps/
COPY pkg/          pkg/
COPY go.work       go.work
COPY go.work.sum   go.work.sum

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    set -e && \
    # go.work references tests/* + tools/* + scripts/gen-source-icon which we
    # don't ship in the builder context (only apps/ + pkg/ get COPYed). Strip
    # those use entries so workspace mode loads without the missing dirs.
    sed -i -E '/^\s*\.\/(tests|tools|scripts)\//d' go.work && \
    go build \
        -ldflags="-s -w -X main.version=${VERSION} -X main.defaultBFFConsole=${DEFAULT_BFF_CONSOLE} -X main.defaultConsoleWeb=${DEFAULT_CONSOLE_WEB}" \
        -o /out/calabi \
        ./apps/client/cmd/calabi

# ============================================================================
# Stage 2 - runtime
# ============================================================================
FROM alpine:3.20
LABEL org.opencontainers.image.title="calabi" \
      org.opencontainers.image.description="Calabi tunnel client (calabi CLI + local daemon)" \
      org.opencontainers.image.source="https://github.com/calabinet/calabi" \
      org.opencontainers.image.vendor="Calabi"

# ca-certificates: outbound HTTPS to api.calabi.net / the edge TLS handshake.
# tzdata: correct local-time rendering in logs (no forced TZ — this is a
# worldwide end-user CLI, unlike the server images that pin Asia/Shanghai).
# iproute2: `calabi mesh up` (Connect) shells out to `ip` to assign the tun's
# overlay /32 + route 100.64.0.0/10 (mesh/linkconfig_linux.go).
# wireguard-tools: `wg show <ifname>` reads the mesh device's UAPI socket
# (/var/run/wireguard/*.sock, exposed by the datapath) — the primary handshake/
# transfer diagnostic.
# iptables: subnet-router NAT (MESH.7) MASQUERADEs mesh traffic to advertised
# LAN CIDRs. All unused by the http/tcp tunnel path; kept in the single client
# image so mesh works + is debuggable out of the box.
RUN apk add --no-cache ca-certificates tzdata iproute2 wireguard-tools iptables && \
    addgroup -S calabi && adduser -S -G calabi -h /home/calabi calabi

# HOME must point at a writable dir for the non-root `calabi` user — the daemon
# stores its config / credentials / pidfile / device id under $HOME (Docker does
# NOT set HOME from the passwd entry, so without this it defaults to "/" and the
# daemon can't persist anything).
ENV HOME=/home/calabi
# Tell the binary it's running in a container: `daemon install` is meaningless
# here (no OS service manager), so the daemon runs in the FOREGROUND instead and
# the container runtime supervises it. Also enables the install→foreground
# translation so a stray `daemon install --api-key …` start command still works.
ENV CALABI_IN_CONTAINER=1

# The local daemon serves its read/write console on :7400. Publish with
# `-p 7400:7400` (and set CALABI_STATUS_ADDR=0.0.0.0:7400) to reach the browser
# UI; not required for headless agent use.
EXPOSE 7400

COPY --from=builder /out/calabi /usr/local/bin/calabi

USER calabi:calabi
# `calabi` is the entrypoint, so image args are calabi subcommands. The default
# command runs the long-lived daemon as an API-key AGENT — supply the key via
# the environment and the container stays online + serves your tunnels:
#   docker run -d -e CALABI_API_KEY=tk_… calabinet/calabi:latest
# Override the command for a one-off foreground tunnel:
#   docker run --rm -it -e CALABI_API_KEY=tk_… calabinet/calabi:latest http 8080
ENTRYPOINT ["/usr/local/bin/calabi"]
CMD ["daemon"]
