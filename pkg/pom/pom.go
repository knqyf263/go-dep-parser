package pom

import (
	"encoding/xml"
	"fmt"
	"io"
	"reflect"
	"strings"
)

type pom struct {
	filePath string
	content  *pomXML
}

func (p *pom) merge(result analysisResult) {
	// Merge properties
	p.content.Properties = mergeMaps(result.properties, p.content.Properties)

	art := p.artifact().inherit(result.artifact)

	p.content.GroupId = art.GroupID
	p.content.ArtifactId = art.ArtifactID
	p.content.Version = art.Version.String()
}

func (p pom) properties() properties {
	props := p.content.Properties
	return mergeMaps(props, p.projectProperties())
}

func (p pom) projectProperties() map[string]string {
	val := reflect.ValueOf(p.content).Elem()
	props := p.listProperties(val)

	// https://maven.apache.org/pom.html#properties
	projectProperties := map[string]string{}
	for k, v := range props {
		// e.g. ${project.groupId}
		key := fmt.Sprintf("project.%s", k)
		projectProperties[key] = v

		// It is deprecated, but still available.
		// e.g. ${groupId}
		projectProperties[k] = v
	}

	return projectProperties
}

func (p pom) listProperties(val reflect.Value) map[string]string {
	props := map[string]string{}
	for i := 0; i < val.NumField(); i++ {
		f := val.Type().Field(i)

		tag, ok := f.Tag.Lookup("xml")
		if !ok || strings.Contains(tag, ",") {
			// e.g. ",chardata"
			continue
		}

		switch f.Type.Kind() {
		case reflect.Slice:
			continue
		case reflect.Map:
			m := val.Field(i)
			for _, e := range m.MapKeys() {
				v := m.MapIndex(e)
				props[e.String()] = v.String()
			}
		case reflect.Struct:
			nestedProps := p.listProperties(val.Field(i))
			for k, v := range nestedProps {
				key := fmt.Sprintf("%s.%s", tag, k)
				props[key] = v
			}
		default:
			props[tag] = val.Field(i).String()
		}
	}
	return props
}

func (p pom) artifact() artifact {
	return newArtifact(p.content.GroupId, p.content.ArtifactId, p.content.Version, p.content.Properties)
}

func (p pom) repositories() []string {
	var urls []string
	for _, rep := range p.content.Repositories.Repository {
		if rep.Releases.Enabled != "false" {
			urls = append(urls, rep.URL)
		}
	}
	return urls
}

type pomXML struct {
	Parent     pomParent `xml:"parent"`
	GroupId    string    `xml:"groupId"`
	ArtifactId string    `xml:"artifactId"`
	Version    string    `xml:"version"`
	Modules    struct {
		Text   string   `xml:",chardata"`
		Module []string `xml:"module"`
	} `xml:"modules"`
	Properties           properties `xml:"properties"`
	DependencyManagement struct {
		Text         string          `xml:",chardata"`
		Dependencies pomDependencies `xml:"dependencies"`
	} `xml:"dependencyManagement"`
	Dependencies pomDependencies `xml:"dependencies"`
	Repositories struct {
		Text       string `xml:",chardata"`
		Repository []struct {
			Text     string `xml:",chardata"`
			ID       string `xml:"id"`
			Name     string `xml:"name"`
			URL      string `xml:"url"`
			Releases struct {
				Text    string `xml:",chardata"`
				Enabled string `xml:"enabled"`
			} `xml:"releases"`
			Snapshots struct {
				Text    string `xml:",chardata"`
				Enabled string `xml:"enabled"`
			} `xml:"snapshots"`
		} `xml:"repository"`
	} `xml:"repositories"`
}

type pomParent struct {
	GroupId      string `xml:"groupId"`
	ArtifactId   string `xml:"artifactId"`
	Version      string `xml:"version"`
	RelativePath string `xml:"relativePath"`
}

type pomDependencies struct {
	Text       string          `xml:",chardata"`
	Dependency []pomDependency `xml:"dependency"`
}

type pomDependency struct {
	Text       string `xml:",chardata"`
	GroupId    string `xml:"groupId"`
	ArtifactId string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
	Optional   bool   `xml:"optional"`
}

type properties map[string]string

type property struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

func (props *properties) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	*props = properties{}
	for {
		var p property
		err := d.Decode(&p)
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		(*props)[p.XMLName.Local] = p.Value
	}
	return nil
}
