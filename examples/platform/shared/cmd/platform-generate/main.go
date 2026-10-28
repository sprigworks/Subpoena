// Command platform-generate writes the shared Grafana provisioning file.
package main

import (
	"log"
	"os"

	"example.com/platform/contract/alerts"
)

func main() {
	b, err := alerts.Render()
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile("alerts/rules.yaml", b, 0644); err != nil {
		log.Fatal(err)
	}
}
