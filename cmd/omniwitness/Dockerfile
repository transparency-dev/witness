FROM golang:1.21-alpine@sha256:926f7f7e1ab8509b4e91d5ec6d5916ebb45155b0c8920291ba9f361d65385806 AS builder
RUN apk add --no-cache gcc musl-dev

ARG GOFLAGS=""
ENV GOFLAGS=$GOFLAGS
ENV GO111MODULE=on

# Move to working directory /build
WORKDIR /build

# Copy and download dependency using go mod
COPY go.mod .
COPY go.sum .
RUN go mod download

# Copy the code into the container
COPY . .

# Build the application
RUN go build -o bin/omniwitness ./cmd/omniwitness

# Build release image
FROM alpine:3.18.4@sha256:eece025e432126ce23f223450a0326fbebde39cdf496a85d8c016293fc851978

COPY --from=builder /build/bin/omniwitness /bin/omniwitness
ENTRYPOINT ["/bin/omniwitness"]
