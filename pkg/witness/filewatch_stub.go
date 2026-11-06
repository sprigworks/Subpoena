package witness

import "errors"

// FileWatch: API only until the tests exist.
type FileWatch struct{ hooks fileHooks }

type fileHooks struct {
	hold     chan struct{}
	addWatch func(fd int, path string, mask uint32) (int, error)
	readDir  func(string) ([]string, error)
}

func NewFileWatch(roots ...string) (*FileWatch, error)                  { return nil, errors.New("not built") }
func newFileWatch(h fileHooks, roots ...string) (*FileWatch, error)     { return nil, errors.New("not built") }
func (w *FileWatch) Stop() error                                        { return nil }
func (w *FileWatch) Wrote(string) []FileEvent                           { return nil }
func (w *FileWatch) Covers(string) bool                                 { return false }
func (w *FileWatch) Health() error                                      { return nil }
func (w *FileWatch) Coverage() FileCoverage                             { return FileCoverage{} }
