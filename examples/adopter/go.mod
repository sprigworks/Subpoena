module example.com/jobrunner

go 1.24.0

require (
	github.com/sprigworks/subpoena v0.0.0-00010101000000-000000000000
	go.opentelemetry.io/otel v1.35.0
	go.opentelemetry.io/otel/trace v1.35.0
)

require (
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/otel/metric v1.35.0 // indirect
	go.opentelemetry.io/otel/sdk v1.35.0 // indirect
	golang.org/x/sys v0.37.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// Developed inside the Subpoena repository; a real adopter requires a
// released version instead.
replace github.com/sprigworks/subpoena => ../..

tool (
	github.com/sprigworks/subpoena/cmd/subpoena-gate
	github.com/sprigworks/subpoena/cmd/subpoena-invgen
	github.com/sprigworks/subpoena/cmd/subpoena-lint
)
