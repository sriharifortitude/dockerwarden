# syntax=docker/dockerfile:1
FROM golang:1.22.7-bookworm@sha256:0000000000000000000000000000000000000000000000000000000000000000 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/app ./cmd/app

FROM gcr.io/distroless/static-debian12:nonroot@sha256:0000000000000000000000000000000000000000000000000000000000000000
COPY --from=build /out/app /app
USER 65532:65532
ENTRYPOINT ["/app"]
