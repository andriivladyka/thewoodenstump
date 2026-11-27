# One image per service: docker build --build-arg SERVICE=board .
FROM golang:1.26 AS build
ARG SERVICE
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/app ./services/${SERVICE}
# An empty, writable /data: mcp-local keeps its wallet key there, and a named
# Docker volume mounted on it starts out owned by the nonroot user.
RUN mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/app /app
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
ENTRYPOINT ["/app"]
