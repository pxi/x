// Chenv is a simple environment switcher. It is intended to work as an
// extension to built-in shell commands `cd`, `pushd`, and `popd`.
//
// For basic usage, add something like the following to the shell startup
// scripts:
//   _chenv() {
//     builtin "$@" || return $?
//     eval "$(chenv "$OLDPWD" "$PWD")"
//   }
//   cd() { _chenv cd "$@"; }
//   popd() { _chenv popd "$@"; }
//   pushd() { _chenv pushd "$@"; }
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/template"

	"github.com/pxi/x/envrc"
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: %s [flags] <src> <dst>\n", os.Args[0])
	flag.PrintDefaults()
}

func main() {
	flag.StringVar(&envrc.Name, "f", envrc.Name, "name of the envrc file")
	flag.Usage = usage
	flag.Parse()

	if flag.NArg() != 2 {
		flag.Usage()
		os.Exit(2)
	}

	src := flag.Arg(0)
	dst := flag.Arg(1)
	if err := chenv(os.Stdout, src, dst); err != nil {
		fmt.Fprintf(os.Stderr, "chenv: %v\n", err)
		os.Exit(1)
	}
}

const text = `builtin pushd {{.Path}} >/dev/null 2>&1
{{.Data}}
builtin popd >/dev/null 2>&1
` // Keep this last line in here!

func chenv(w io.Writer, a, b string) error {
	var buf strings.Builder
	script := template.Must(template.New("script").Parse(text))
	if err := envrc.Chdir(a, b, func(path, data string) {
		if data != "" {
			if e := script.Execute(&buf, struct {
				Path string
				Data string
			}{path, data}); e != nil {
				panic(e)
			}
		}
	}); err != nil {
		return err
	}
	_, err := io.WriteString(w, buf.String())
	return err
}
