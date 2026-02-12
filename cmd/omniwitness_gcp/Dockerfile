FROM golang:1.25-alpine@sha256:f6751d823c26342f9506c03797d2527668d095b0a15f1862cddb4d927a7a4ced AS builder

ARG GOFLAGS=""
ENV GOFLAGS=$GOFLAGS

# Move to working directory /build
WORKDIR /build

# Copy and download dependency using go mod
COPY go.mod .
COPY go.sum .
RUN go mod download

# Copy the code into the container
COPY . .

# Build the application
RUN go build -o bin/omniwitness ./cmd/omniwitness_gcp

# Build release image
FROM us-central1-docker.pkg.dev/serverless-runtimes/google-22/runtimes/go125:go125_20260112_1_25_5_RC00@sha256:d291dbb18c0df459bda069029f70f00f66cc945ae5d70be5c2a8e5b4c3846f98

COPY --from=builder /build/bin/omniwitness /bin/omniwitness
ENTRYPOINT ["/bin/omniwitness"]
