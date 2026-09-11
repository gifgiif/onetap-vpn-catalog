FROM golang:1.25-alpine AS api-build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /api ./cmd/api

FROM golang:1.25-alpine AS xray-build
ARG XRAY_VERSION=26.9.9
RUN GOBIN=/out go install github.com/xtls/xray-core/main@v${XRAY_VERSION} && mv /out/main /out/xray

FROM gcr.io/distroless/base-debian12
COPY --from=api-build /api /api
COPY --from=xray-build /out/xray /usr/local/bin/xray
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/api"]
