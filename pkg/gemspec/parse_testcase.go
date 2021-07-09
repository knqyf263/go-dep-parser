package gemspec

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	GemspecNormal = []types.Library{
		{"async", "1.25.0"},
	}

	GemspecMalformed = []types.Library{}
)
