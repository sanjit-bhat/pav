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

var dump = flag.Bool("dump", false, "dump golden ast [for dev]")

type entry struct {
	source, golden string
	runs           int
}

var data = []entry{
	//{"ints/ints.go", "ints/ints.golden", 1},
	//{"alias/alias.go", "alias/alias.golden", 1},
	//{"mult/mult.go", "mult/mult.golden", 3},
	//{"otherpkg/otherpkg.go", "otherpkg/otherpkg.golden", 1},
	//{"bool/bool.go", "bool/bool.golden", 1},
	{"slice/slice.go", "slice/slice.golden", 1},
}

// tmpWrite writes data to a tmp file and returns the tmp file name.
func tmpWrite(data []byte) (string, error) {
	f, err := os.CreateTemp("", "")
	defer f.Close()
	if err != nil {
		return "", err
	}
	_, err = f.Write(data)
	if err != nil {
		return "", err
	}
	return f.Name(), nil
}

func check(t *testing.T, source, golden string) {
	if *dump {
		gld, err := os.ReadFile(golden)
		if err != nil {
			t.Error(err)
			return
		}
		res := printAst(gld)
		t.Logf("golden ast dump:\n%s", res)
	}

	res := compile(source)
	actual, err := tmpWrite(res)
	if err != nil {
		t.Error(err)
		return
	}

	cmd := exec.Command("diff", "--unified", actual, golden)
	diff, err := cmd.CombinedOutput()
	if err != nil {
		t.Errorf("actual output diff from golden:\n%s", diff)
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
