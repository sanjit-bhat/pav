package main

import (
	"flag"
	"log"
	"os"
	"strings"
)

var in = flag.String("in", "", "required path to input file")
var out = flag.String("out", "", "optional path to output file")

func main() {
	log.SetFlags(log.Lshortfile)
	flag.Parse()
	if *in == "" {
		log.Panic("empty input file. maybe there was no input arg?")
	}
	res := compile(*in)
	if *out == "" {
		*out = strings.Replace(*in, ".go", ".out.go", 1)
	}
	if err := os.WriteFile(*out, res, 0644); err != nil {
		log.Panic("failed to write to output file: ", *out)
	}
	log.Print("wrote to output file: ", *out)
}
