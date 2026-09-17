FROM golang:1.26.8-alpine3.24@sha256:ce864e7223ac17b1775e6fd0b4c0db580c2eb50e7953a427916379e4b92a1628 AS builder

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
FROM us-central1-docker.pkg.dev/serverless-runtimes/google-24/runtimes/go126:go126_20260902_1_26_7_RC00@sha256:21f91aa435b5128f0c9b764d76fc98d163156cf96e099e783f870a3761acd2e6

COPY --from=builder /build/bin/omniwitness /bin/omniwitness
ENTRYPOINT ["/bin/omniwitness"]
