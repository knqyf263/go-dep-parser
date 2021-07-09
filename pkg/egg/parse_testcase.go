package egg

import "github.com/aquasecurity/go-dep-parser/pkg/types"

var (
	// listing dependencies based on egg-info or PKG-INFO files
	// docker run --name poetry --rm -it jonatkinson/python-poetry:3.7 bash
	// find / -wholename "*egg-info" | xargs -I {} sh -c 'cat {} | awk 'NR==2,NR==3'' | tee PKG-INFOS
	// find / -wholename "*egg-info/PKG-INFO" | xargs -I {} sh -c 'cat {} | awk 'NR==2,NR==3'' | tee -a PKG-INFOS
	// cat PKG-INFOS | awk 'BEGIN {FS=" "} {print $2}' | awk '!(NR%2){printf("{\""p"\", \""$0"\"},\n")}{p=$0}' | sort | uniq

	// copying relevant metadata files for tests
	// mkdir egg-infos
	// find / -name "*egg-info" | xargs -I % cp -r % egg-infos/
	// find egg-infos/ | grep txt | xargs rm

	// for single egg-info file with known name
	// cat "{{ libname }}.egg-info" | awk 'NR==2,NR==3' | awk 'BEGIN {FS=" "} {print $2}' | awk '!(NR%2){printf("{\""p"\", \""$0"\"},\n")}{p=$0}'
	EggEggInfo = []types.Library{
		{"Python", "2.7.13"},
	}

	// for single PKG-INFO file with known name
	// cat "{{ libname }}.egg-info.PKG-INFO" | awk 'NR==2,NR==3' | awk 'BEGIN {FS=" "} {print $2}' | awk '!(NR%2){printf("{\""p"\", \""$0"\"},\n")}{p=$0}'
	EggEggInfoPkgInfo = []types.Library{
		{"awscli", "1.19.12"},
	}
)
