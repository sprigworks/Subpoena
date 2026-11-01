FROM golang:1.25 AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -buildvcs=false -o /out/subpoena-witness ./cmd/subpoena-witness
RUN CGO_ENABLED=0 go build -buildvcs=false -o /out/capture ./conformance/oatscapture

FROM scratch
COPY --from=build /out/subpoena-witness /subpoena-witness
COPY --from=build /out/capture /capture
ENTRYPOINT ["/capture"]
