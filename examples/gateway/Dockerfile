# Build context is the repository root:
#   docker build -f examples/gateway/Dockerfile -t subpoena-gateway .
FROM golang:1.25 AS build
WORKDIR /src
COPY . .
# Normal environments can use the default proxy. In a sandbox without
# proxy.golang.org, build with: --build-arg GOPROXY=direct --build-arg GOSUMDB=off
ARG GOPROXY=https://proxy.golang.org,direct
ARG GOSUMDB=sum.golang.org
RUN CGO_ENABLED=0 go build -o /out/gateway ./examples/gateway/cmd/gateway

# The gateway execs echo, true and sleep, so the runtime image needs coreutils.
FROM debian:bookworm-slim
COPY --from=build /out/gateway /usr/local/bin/gateway
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/gateway"]
