FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /oauth-husk .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /oauth-husk /usr/local/bin/oauth-husk
VOLUME /var/lib/oauth-husk
EXPOSE 8200
ENTRYPOINT ["oauth-husk"]
CMD ["serve", "--port", "8200", "--db", "/var/lib/oauth-husk/oauth.db"]
