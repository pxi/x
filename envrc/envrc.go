// Package envrc implements parsing of envrc files.
//
// Envrc file is a simple text file with shell commands. Different sections
// are separater with a section header. Lines before any section header are
// common for every sections.
//
// Given an example envrc file:
//
//     # These lines will be included for both sections.
//     foo="foo"
//     bar="bar"
//
//     enter:
//     export foo
//     echo $bar
//
//     exit:
//     unset foo
//     echo $bar
//
// When enter section is evaluated, the resulting shell script would be:
//
//     foo="foo"
//     bar="bar"
//     export foo
//     echo $bar
//
// When exit section is evaluated, the resulting shell script would be:
//
//     foo="foo"
//     bar="bar"
//     unset foo
//     echo $bar
//
package envrc

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Parse returns the parsed enter and exit sections from r.
func Parse(r io.Reader) (string, string, error) {
	scan := bufio.NewScanner(r)
	scan.Split(scanLines)

	hbuf := new(strings.Builder)
	ebuf := new(strings.Builder)
	xbuf := new(strings.Builder)

	target := hbuf
	for scan.Scan() {
		line := scan.Text()
		switch {
		case strings.HasPrefix(line, "enter:"):
			target = ebuf
			continue
		case strings.HasPrefix(line, "exit:"):
			target = xbuf
			continue
		default:
			if _, err := target.WriteString(line); err != nil {
				return "", "", err
			}
		}
	}
	if err := scan.Err(); err != nil {
		return "", "", err
	}

	trim := func(s string) string {
		s = strings.TrimLeft(s, "\n")
		s = strings.TrimRight(s, "\n")
		return s
	}

	enter := hbuf.String() + ebuf.String()
	exit := hbuf.String() + xbuf.String()

	return trim(enter), trim(exit), nil
}

// scanLines is a split function for bufio.Scanner that returns each line of
// text. It differs from bufio.ScanLines so that this version does not strip
// end-of-line markers.
func scanLines(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		// We have a full newline-terminated line.
		return i + 1, data[0 : i+1], nil
	}
	// If we're at EOF, we have a final, non-terminated line. Return it.
	if atEOF {
		return len(data), data, nil
	}
	// Request more data.
	return 0, nil, nil
}

// Name is the name of the envrc file.
var Name = ".envrc"

func eval(path string) (string, string, error) {
	path = filepath.Join(path, Name)
	f, err := os.Open(path)
	if err != nil && os.IsNotExist(err) {
		return "", "", nil
	}
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	es, xs, err := Parse(f)
	if err != nil {
		err = fmt.Errorf("envrc: %s: %v", path, err)
	}
	return es, xs, err
}

const sep = string(os.PathSeparator)

// Chdir changes the environment between a and b directories. The given
// chdir callback is called for every required path change.
func Chdir(a, b string, chdir func(path, data string)) error {
	a = filepath.Clean(a)
	b = filepath.Clean(b)

	r, err := filepath.Rel(a, b)
	if err != nil {
		return err
	}

	hops := append([]string{a}, strings.Split(r, sep)...)
	for i := 1; i < len(hops); i++ {
		hop := hops[i]

		// Expand this hop to an absolute path.
		hops[i] = filepath.Join(hops[i-1], hops[i])

		var (
			path string
			data string
			err  error
		)

		if hop == ".." {
			path = hops[i-1]
			_, data, err = eval(path)
		} else {
			path = hops[i]
			data, _, err = eval(path)
		}

		if err != nil {
			return err
		}

		if data != "" {
			chdir(path, data)
		}
	}
	return nil
}
