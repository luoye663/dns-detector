FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o dns-detector .

FROM alpine:3.19
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /app
COPY --from=builder /app/dns-detector .
COPY index.html .

EXPOSE 8080 53/udp 53/tcp

ENV DNS_DOMAIN=dns.example.com
ENV NS_IP=1.2.3.4
ENV WEB_PORT=:8080
ENV DNS_PORT=:53

CMD ["./dns-detector"]
