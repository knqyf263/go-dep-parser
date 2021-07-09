package gemspec

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

var (
	specConstructorStr = "Gem::Specification.new"
)

func Parse(r io.Reader) ([]types.Library, error) {
	var libs []types.Library
	var gemspecLib types.Library
	constructorVar := ""
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if constructorVar == "" {
			if strings.Contains(line, specConstructorStr) {
				constructorVar = substringBetween(line, "|")
			}
		} else {
			if strings.Contains(line, fmt.Sprintf("%s.name", constructorVar)) {
				gemspecLib.Name = parseAttributeValue(line)
			}
			if strings.Contains(line, fmt.Sprintf("%s.version", constructorVar)) {
				gemspecLib.Version = parseAttributeValue(line)
			}
		}
		if gemspecLib.Name != "" && gemspecLib.Version != "" {
			libs = append(libs, gemspecLib)
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return libs, nil
}

func parseAttributeValue(line string) string {
	value := substringBetween(line, "\"")
	if value != "" {
		return value
	}
	return substringBetween(line, "'")
}

func substringBetween(line string, char string) string {
	regexpString := fmt.Sprintf("\\%s(.*?)\\%s", char, char)
	re := regexp.MustCompile(regexpString)
	rs := re.FindStringSubmatch(line)
	if len(rs) == 2 {
		return rs[1]
	}
	return ""
}
