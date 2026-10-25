//go:build !(linux && (amd64 || arm64))

package execbpf

import "errors"

type kernel struct{}

// Start fails: the program is built for Linux on amd64 and arm64 only.
func (w *Witness) Start() error {
	return errors.New("execbpf: needs Linux on amd64 or arm64")
}

// Stop does nothing.
func (w *Witness) Stop() error { return nil }
