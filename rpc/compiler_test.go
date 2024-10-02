package main

import (
	"flag"
	"os"
	"os/exec"
	"path"
	"testing"
)

const (
	dataDir = "testdata"
)

var update = flag.Bool("update", false, "update golden files")

type entry struct {
	source, golden string
	runs           int
}

var data = []entry{
	{"types/types.go", "types/types.golden.go", 1},
	{"alias/alias.go", "alias/alias.golden.go", 1},
	{"mult/mult.go", "mult/mult.golden.go", 3},
	{"nogen/nogen.go", "nogen/nogen.golden.go", 1},
	{"const/const.go", "const/const.golden.go", 1},
}

// tmpWrite writes data to a tmp file and returns the tmp file name.
func tmpWrite(t *testing.T, data []byte) string {
	f, err := os.CreateTemp("", "")
	defer func() {
		err := f.Close()
		if err != nil {
			t.Error(err)
		}
	}()
	if err != nil {
		t.Error(err)
		return ""
	}
	_, err = f.Write(data)
	if err != nil {
		t.Error(err)
		return ""
	}
	return f.Name()
}

func check(t *testing.T, source, golden string) {
	res := compile(source)
	actual := tmpWrite(t, res)

	cmd := exec.Command("diff", "--unified", "--color=always", golden, actual)
	diff, err := cmd.CombinedOutput()
	if err != nil {
		t.Errorf("diff from golden to actual output:\n%s", diff)
	}

	err = os.Remove(actual)
	if err != nil {
		t.Error(err)
	}

	if *update {
		if err := os.WriteFile(golden, res, 0644); err != nil {
			t.Error(err)
		}
		t.Log("updated: ", golden)
	}
}

func TestFiles(t *testing.T) {
	t.Parallel()
	for _, e := range data {
		source := path.Join(dataDir, e.source)
		golden := path.Join(dataDir, e.golden)
		t.Run(e.source, func(t *testing.T) {
			t.Parallel()
			for i := 0; i < e.runs && !t.Failed(); i++ {
				check(t, source, golden)
			}
		})
	}
}
