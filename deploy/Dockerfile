FROM golang:1.24-alpine AS build
ENV GOTOOLCHAIN=auto
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /wafguard ./cmd/wafguard

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /wafguard /wafguard
EXPOSE 12345 9090
CMD ["/wafguard", "-config", "/etc/wafguard/config.json"]

