FROM golang:1.24-alpine AS build
ENV GOTOOLCHAIN=auto
WORKDIR /src
COPY go.mod go.sum ./
COPY integration/testorigin ./integration/testorigin
RUN go build -o /testorigin ./integration/testorigin

FROM alpine:3.20
COPY --from=build /testorigin /testorigin
EXPOSE 8081
ENTRYPOINT ["/testorigin"]

