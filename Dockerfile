FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o /aguara ./cmd/aguara

FROM alpine:3.21
COPY --from=builder /aguara /usr/local/bin/aguara
ENTRYPOINT ["aguara"]
CMD ["scan", "."]
