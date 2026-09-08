FROM golang:1.27-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125 AS builder

ARG GOFLAGS=""
ENV GOFLAGS=$GOFLAGS
ENV CGO_ENABLED=0

# Move to working directory /build
WORKDIR /build

# Copy and download dependency using go mod
COPY go.mod go.sum .
RUN go mod download

# Copy the code into the container
COPY . .

# Build the application
RUN go build -trimpath -ldflags="-s -w" -o bin/omniwitness ./cmd/omniwitness

# Created here: the release image has no shell to mkdir with.
RUN mkdir -p /build/data

# Build release image.
# No shell, no package manager, uid/gid 65532, ships CA certificates.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7

COPY --from=builder --chown=65532:65532 /build/data /data
COPY --from=builder /build/bin/omniwitness /bin/omniwitness

USER 65532:65532

# Defaults of --listen and --metrics_listen; both >1024.
EXPOSE 8080 8081

ENTRYPOINT ["/bin/omniwitness"]
