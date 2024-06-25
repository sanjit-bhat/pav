package main

import (
	"bytes"
	"flag"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"os"
)

var dump = flag.String("dump", "", "dump ast of the provided file [for dev]")

func main() {
	log.SetFlags(log.Lshortfile)
	flag.Parse()
	if *dump == "" {
		return
	}
	f, err := os.ReadFile(*dump)
	if err != nil {
		log.Panic(err)
		return
	}
	res := printAst(f)
	log.Printf("ast dump for %s:\n%s", *dump, res)
}

func printAst(src []byte) []byte {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "", src, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		log.Panic(err)
	}
	res := new(bytes.Buffer)
	ast.Fprint(res, fset, f, ast.NotNilFilter)
	return res.Bytes()
}
