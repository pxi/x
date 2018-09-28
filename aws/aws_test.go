package aws

import (
	"bufio"
	"context"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseHost(t *testing.T) {
	tests := []struct {
		host    string
		service string
		region  string
	}{
		{"", "", ""},
		{"myhost.com", "", ""},
		{"amazonaws.com", "", ""},
		{"generic.eu-west-1.amazonaws.com", "generic", EUWest1},
		{"eu-west-1.generic.amazonaws.com", "generic", EUWest1},
		{"generic-eu-west-1.amazonaws.com", "generic", EUWest1},
		{"s3.amazonaws.com", "s3", USEast1},
		{"s3-external-1.amazonaws.com", "s3", USEast1},
		{"some.bucket.s3.amazonaws.com", "s3", USEast1},
	}
	for _, test := range tests {
		host := test.host
		wantRegion := test.region
		wantService := test.service
		region, service := ParseHost(host)
		if region != wantRegion || service != wantService {
			t.Errorf("ParseHost(%q):\n got: %q %q\nwant: %q %q", host, region, service, wantRegion, wantService)
		}
	}
}

var skipSuite = map[string]struct{}{
	// Go does not allow spaces in the request line.
	"get-space": struct{}{},

	// Support for multiline HTTP headers has been abandoned. See
	// https://tools.ietf.org/html/rfc7230#section-3.2.4 for more info.
	"get-header-value-multiline": struct{}{},

	// Session does not care about what happens after Sign.
	"post-sts-header-after": struct{}{},

	// BUG(pxi): these are still failing.
	"post-x-www-form-urlencoded":            struct{}{},
	"post-x-www-form-urlencoded-parameters": struct{}{},
}

//go:generate go run suite_test_gen.go
func TestSessionSign(t *testing.T) {
	now = func() time.Time {
		return time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	}

	const (
		kid     = "AKIDEXAMPLE"
		key     = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
		region  = "us-east-1"
		service = "service"
	)

	opts := []Option{
		WithRegion(region),
		WithService(service),
		WithCredentials(kid, key, ""),
	}

	s, err := NewSession(context.Background(), opts...)
	if err != nil {
		t.Fatal(err)
	}

	for i := range suiteTests {
		c := suiteTests[i]
		t.Run(c, func(t *testing.T) {
			if _, skip := skipSuite[c]; skip {
				t.SkipNow()
			}

			t.Parallel()

			baseName := filepath.Join("testdata", c)

			req := readRequest(t, baseName+".req")
			sreq := readRequest(t, baseName+".sreq")

			creq, sts, err := s.sign(req)
			if err != nil {
				t.Fatal(err)
			}

			if want := readFile(t, baseName+".creq"); creq != want {
				t.Fatalf("canonical request:\ngot:\n%s\nwant:\n%s", creq, want)
			}

			if want := readFile(t, baseName+".sts"); sts != want {
				t.Fatalf("string to sign:\ngot:\n%s\nwant:\n%s", sts, want)
			}

			got := dumpRequest(t, req)
			want := dumpRequest(t, sreq)
			if got != want {
				t.Fatalf("signed request:\ngot:\n%s\nwant:\n%s", got, want)
			}
		})
	}
}

func readRequest(tb testing.TB, path string) *http.Request {
	tb.Helper()
	rd := strings.NewReader(readFile(tb, path))
	r, err := http.ReadRequest(bufio.NewReader(rd))
	if err != nil {
		tb.Fatal(err)
	}
	return r
}

func readFile(tb testing.TB, path string) string {
	tb.Helper()
	b, err := ioutil.ReadFile(path)
	if err != nil {
		tb.Fatal(err)
	}
	return string(b)
}

func dumpRequest(tb testing.TB, req *http.Request) string {
	tb.Helper()
	b, err := httputil.DumpRequest(req, true)
	if err != nil {
		tb.Fatal(err)
	}
	return string(b)
}
