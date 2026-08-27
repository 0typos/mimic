# syntax=docker/dockerfile:1

FROM golang:1.25.0-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY lab ./lab
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=lab" -o /out/mimic ./cmd/mimic
RUN CGO_ENABLED=0 go build -tags lab -trimpath -ldflags="-s -w" -o /out/lab-origin ./lab/cmd/lab-origin

FROM alpine:3.22 AS mimic
RUN apk add --no-cache ca-certificates
COPY --from=build /out/mimic /usr/local/bin/mimic
COPY --from=build /out/lab-origin /usr/local/bin/lab-origin
COPY lab/start-mimic.sh /usr/local/bin/start-mimic
ENTRYPOINT ["/usr/local/bin/start-mimic"]

FROM scratch AS origin
COPY --from=build /out/lab-origin /lab-origin
EXPOSE 8080 8443 9443
ENTRYPOINT ["/lab-origin", "serve"]
