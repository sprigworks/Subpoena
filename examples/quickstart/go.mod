module example.com/quickstart

go 1.25.0

require (
	github.com/sprigworks/subpoena v0.0.0-00010101000000-000000000000
	go.opentelemetry.io/otel v1.45.0
	go.opentelemetry.io/otel/trace v1.45.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel/metric v1.45.0 // indirect
	go.opentelemetry.io/otel/sdk v1.45.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

// Developed inside the Subpoena repository; a real adopter requires a
// released version instead.
replace github.com/sprigworks/subpoena => ../..

tool github.com/sprigworks/subpoena/cmd/subpoena-cross
