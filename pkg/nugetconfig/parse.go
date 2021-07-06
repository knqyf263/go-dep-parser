package nugetconfig

import (
	"encoding/xml"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"golang.org/x/xerrors"
	"io"
)

type Dependencies map[string]Dependency

type Dependency struct {
	Type     string
	Resolved string
}

type cfgPackageReference struct {
	XMLName         xml.Name `xml:"package"`
	TargetFramework string   `xml:"targetFramework,attr"`
	Version         string   `xml:"version,attr"`
	ID              string   `xml:"id,attr"`
}

type config struct {
	XMLName  xml.Name              `xml:"packages"`
	Packages []cfgPackageReference `xml:"package"`
}

func Parse(r io.Reader) ([]types.Library, error) {
	var cfgData config
	uniqueLibs := map[types.Library]struct{}{}
	if err := xml.NewDecoder(r).Decode(&cfgData); err != nil {
		return nil, xerrors.Errorf("failed to decode .config file: %w", err)
	}

	for _, cfgPackageReference := range cfgData.Packages {
		name := cfgPackageReference.ID
		version := cfgPackageReference.Version
		if name != "" {
			lib := types.Library{
				Name:    name,
				Version: version,
			}
			uniqueLibs[lib] = struct{}{}
		}
	}

	var libraries []types.Library
	for lib := range uniqueLibs {
		libraries = append(libraries, lib)
	}

	return libraries, nil
}
