package gemspec

import (
	"os"
	"path"
	"testing"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

func TestParse(t *testing.T) {
	vectors := []struct {
		file      string // Test input file
		libraries []types.Library
	}{
		{
			file:      "testdata/normal00.gemspec",
			libraries: GemspecNormal,
		},
		{
			file:      "testdata/normal01.gemspec",
			libraries: GemspecNormal,
		},
		{
			file:      "testdata/normal02.gemspec",
			libraries: GemspecNormal,
		},
		{
			file:      "testdata/malformed00.gemspec",
			libraries: GemspecMalformed,
		},
		{
			file:      "testdata/malformed01.gemspec",
			libraries: GemspecMalformed,
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.file), func(t *testing.T) {
			f, err := os.Open(v.file)
			if err != nil {
				t.Fatalf("Open() error: %v", err)
			}
			libList, err := Parse(f)
			if err != nil {
				t.Fatalf("Parse() error: %v", err)
			}

			if len(libList) != len(v.libraries) {
				t.Fatalf("lib length: got %v, want %v", len(libList), len(v.libraries))
			}

			for i, got := range libList {
				want := v.libraries[i]
				if want.Name != got.Name {
					t.Errorf("%d: Name: got %s, want %s", i, got.Name, want.Name)
				}
				if want.Version != got.Version {
					t.Errorf("%d: Version: got %s, want %s", i, got.Version, want.Version)
				}
			}
		})
	}
}
