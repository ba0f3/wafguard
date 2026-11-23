FROM golang:1.24-alpine AS build
ENV GOTOOLCHAIN=auto
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY integration/recorder ./integration/recorder
RUN go build -o /recorder ./integration/recorder

FROM alpine:3.20
COPY --from=build /recorder /recorder
EXPOSE 12346 18090
ENTRYPOINT ["/recorder"]
