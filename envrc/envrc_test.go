package envrc

import (
	"strconv"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		file  string
		enter string
		exit  string
	}{
		{"", "", ""},
		{"a", "a", "a"},
		{"enter:\na", "a", ""},
		{"exit:\na", "", "a"},
		{"enter:\na\nexit:\nb", "a", "b"},
		{"a\nenter:\na\nexit:\nb", "a\na", "a\nb"},
	}

	for i := range tests {
		c := tests[i]
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			enter, exit, err := Parse(strings.NewReader(c.file))
			if err != nil {
				t.Fatal(err)
			}

			if enter != c.enter {
				t.Errorf("enter section:\n got %#q\nwant %#q", enter, c.enter)
			}
			if exit != c.exit {
				t.Errorf("exit section:\n got %#q\nwant %#q", exit, c.exit)
			}
		})
	}
}
