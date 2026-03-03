FROM golang:1.22-alpine AS builder
WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .
RUN go generate ./...
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/marketplace-service ./cmd/marketplace

FROM alpine:3.20
WORKDIR /app

RUN addgroup -S app && adduser -S app -G app
COPY --from=builder /out/marketplace-service /app/marketplace-service

EXPOSE 8000
USER app
ENTRYPOINT ["/app/marketplace-service"]
