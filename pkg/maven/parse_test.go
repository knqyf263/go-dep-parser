package maven

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

func TestParse(t *testing.T) {
	vectors := []struct {
		file string // Test input file
		want []types.Library
	}{
		{
			file: "testdata/spring.txt",
			want: MavenNormal,
		},
		{
			file: "testdata/hadoop-hdfs-nfs.txt",
			want: MavenHadoopHDFS,
		},
		{
			file: "testdata/hadoop-cloud-storage.txt",
			want: MavenHadoopCloudStorage,
		},
		{
			file: "testdata/none.txt",
			want: MavenNone,
		},
		{
			file: "testdata/classifier.txt",
			want: MavenClassifier,
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.file), func(t *testing.T) {
			f, err := os.Open(v.file)
			require.NoError(t, err)

			got, err := Parse(f)
			require.NoError(t, err)

			assert.Equal(t, v.want, got)
		})
	}
}
