# Base images pinned by multi-arch index digest for reproducible builds.
# Bump digests together with the tag when upgrading (e.g. alpine 3.22).
FROM golang:1.25-alpine@sha256:5caaf1cca9dc351e13deafbc3879fd4754801acba8653fa9540cea125d01a71f AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# VERSION/COMMIT default to "dev"/"none" for local builds without --build-arg.
# CI passes the actual tag and commit so `aguara version` matches the release.
ARG VERSION=dev
ARG COMMIT=none

RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w \
      -X github.com/garagon/aguara/cmd/aguara/commands.Version=${VERSION} \
      -X github.com/garagon/aguara/cmd/aguara/commands.Commit=${COMMIT}" \
    -o /aguara ./cmd/aguara

FROM alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d
COPY --from=builder /aguara /usr/local/bin/aguara

# Run as non-root to limit blast radius on container escape or arbitrary file write bugs.
RUN adduser -D -u 10001 aguara
USER aguara

ENTRYPOINT ["aguara"]
CMD ["scan", "."]
