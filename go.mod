module github.com/sprigworks/subpoena

go 1.24

require (
	go.opentelemetry.io/otel v1.35.0
	go.opentelemetry.io/otel/sdk v1.35.0
	go.opentelemetry.io/otel/trace v1.35.0
)

require (
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/otel/metric v1.35.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
)

replace go.opentelemetry.io/otel => github.com/open-telemetry/opentelemetry-go v1.35.0

replace go.opentelemetry.io/otel/sdk => github.com/open-telemetry/opentelemetry-go/sdk v1.35.0

replace go.opentelemetry.io/otel/trace => github.com/open-telemetry/opentelemetry-go/trace v1.35.0

replace go.opentelemetry.io/otel/metric => github.com/open-telemetry/opentelemetry-go/metric v1.35.0

replace go.opentelemetry.io/auto/sdk => github.com/open-telemetry/opentelemetry-go-instrumentation/sdk v1.1.0

replace golang.org/x/sys => github.com/golang/sys v0.31.0
