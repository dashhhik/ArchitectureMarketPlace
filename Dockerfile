FROM golang:1.22-alpine AS builder
WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/user-identity-service ./cmd/useridentity

FROM alpine:3.20
WORKDIR /app

RUN addgroup -S app && adduser -S app -G app
COPY --from=builder /out/user-identity-service /app/user-identity-service

EXPOSE 8080
USER app
ENTRYPOINT ["/app/user-identity-service"]
