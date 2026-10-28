module example.com/platform/deploy

go 1.25.0

require (
	example.com/platform/contract v0.1.0
	github.com/sprigworks/subpoena v0.0.0-00010101000000-000000000000
	go.opentelemetry.io/otel v1.45.0
	go.opentelemetry.io/otel/sdk v1.45.0
	go.opentelemetry.io/otel/trace v1.45.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel/metric v1.45.0 // indirect
	golang.org/x/mod v0.31.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/tools v0.40.1-0.20260108161641-ca281cf95054 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// Developed inside the Subpoena repository; a real adopter requires a
// released version instead.
replace github.com/sprigworks/subpoena => ../../../..

tool (
	github.com/sprigworks/subpoena/cmd/subpoena-cross
	github.com/sprigworks/subpoena/cmd/subpoena-lint
)

replace example.com/platform/contract => ../../shared
