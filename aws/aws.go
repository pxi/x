package aws

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"time"
)

// Option is a function that sets an option in Config.
type Option func(c *Config)

// Config is a collection of options for AWS access.
type Config struct {
	kid string
	key string
	tok string
}

// Configure returns a new Config with the given options applied.
func Configure(opts ...Option) *Config {
	conf := new(Config)
	conf.SetOptions(opts...)
	return conf
}

// SetOptions applies the given options to the Config.
func (c *Config) SetOptions(opts ...Option) {
	for _, opt := range opts {
		opt(c)
	}
}

// WithKeyID sets the access key ID for Config.
func WithKeyID(s string) Option {
	return func(c *Config) {
		c.kid = s
	}
}

// WithSecretKey sets the secret access key for Config.
func WithSecretKey(s string) Option {
	return func(c *Config) {
		c.key = s
	}
}

// WithSessionToken sets the temporary session token for Config.
func WithSessionToken(s string) Option {
	return func(c *Config) {
		c.tok = s
	}
}

// ErrNoCredentials means that no credentials were found by Config.
var ErrNoCredentials = errors.New("aws: no credentials found")

const (
	dateFormat = "20060102"

	aws4        = "AWS4"
	aws4Request = "aws4_request"
)

// now is a hook for tests to provide a different signing time.
var now func() time.Time = time.Now

// NewSession starts a new session for the given region and service.
func (c *Config) NewSession(region, service string) (*Session, error) {
	kid, key, tok := c.credentials()
	if kid == "" || key == "" {
		return nil, ErrNoCredentials
	}

	date := now().UTC().Format(dateFormat)
	scope := []string{kid, date, region, service, aws4Request}

	s := &Session{
		token: tok,
		scope: scope,
	}

	// Derive the signing key from secret key and scope.
	hash := hmac.New(sha256.New, []byte(aws4+key))
	for i := 1; i < len(scope); i++ {
		hash.Write([]byte(scope[i]))
		if i == len(scope)-1 {
			hash.Sum(s.key[:0])
			break
		}
		hash = hmac.New(sha256.New, hash.Sum(nil))
	}

	return s, nil
}

var (
	accessKeyEnvVars = []string{
		"AWS_ACCESS_KEY_ID",
		"AWS_ACCESS_KEY",
	}
	secretKeyEnvVars = []string{
		"AWS_SECRET_ACCESS_KEY",
		"AWS_SECRET_KEY",
	}
	sessionTokenEnvVars = []string{
		"AWS_SESSION_TOKEN",
	}
)

func (c *Config) credentials() (string, string, string) {
	kid := c.kid
	key := c.key
	tok := c.tok

	maybeLoadFromEnv(&kid, accessKeyEnvVars)
	maybeLoadFromEnv(&key, secretKeyEnvVars)
	maybeLoadFromEnv(&tok, sessionTokenEnvVars)

	return kid, key, tok
}

func maybeLoadFromEnv(s *string, vars []string) {
	vs := *s
	for i := 0; i < len(vars) && vs == ""; i++ {
		vs = os.Getenv(vars[i])
	}
	*s = vs
}

// Session signs HTTP requests using AWS signature version 4.
type Session struct {
	// Expires is the time when the Session expires. Session does not
	// update itself; it is up to the user to request a new Session when
	// a Session is expired.
	Expires time.Time

	token string
	scope []string
	key   [sha256.Size]byte
}

const (
	// TimeFormat is the time format to use when generating times for the
	// DateHeader.
	TimeFormat = "20060102T150405Z"

	// DateHeader is the name of the AWS specific date HTTP header.
	DateHeader = "X-Amz-Date"

	// PayloadHashHeader is the name of AWS specific payload hash HTTP header.
	// Valid values for it are either hex encoded SHA256 sum of the payload
	// or UnsignedPayload.
	PayloadHashHeader = "X-Amz-Content-Sha256"

	// UnsignedPayload can be set to PayloadHashHeader to explicitly instruct
	// AWS to not to consider the payload hash when calculating signatures.
	UnsignedPayload = "UNSIGNED-PAYLOAD"

	securityToken = "X-Amz-Security-Token"
)

// Payload is the type that ensures it can be hashed efficiently without
// additional memory copying.
type Payload interface {
	io.Reader
	io.Seeker
	io.Closer
}

// HashPayload hashes the given payload using SHA256. The returned string can
// be used for the PayloadHashHeader.
func HashPayload(p Payload) (string, error) {
	shaSum := sha256.New()
	_, err := io.Copy(shaSum, p)
	if err != nil {
		return "", err
	}
	_, err = p.Seek(0, 0)
	return hex.EncodeToString(shaSum.Sum(nil)), err
}

// Sign signs the given request.
//
// The req.Body needs to be hashed. Sign replaces the req.Body with a memory
// buffer while hashing except when the req.Body also implements Payload interface;
// then the Seek method is used to rewind the original req.Body after hashing
// is done. This automatic hashing can be prevented by providing a pre-calculated
// hash in the PayloadHashHeader.
//
// A valid date header must be present when sending signed requests to AWS
// services. If neither DateHeader or "Date" header are provided Sign sets the
// DateHeader to current time.
func (s *Session) Sign(req *http.Request) error {
	_, _, err := s.sign(req)
	return err
}

func (s *Session) sign(req *http.Request) (string, string, error) {
	bodyDigest := req.Header.Get(PayloadHashHeader)
	if bodyDigest == "" {
		var err error
		if bodyDigest, err = digestBody(req); err != nil {
			return "", "", err
		}
	}

	reqTime, err := ensureDate(req.Header)
	if err != nil {
		return "", "", err
	}

	if s.token != "" {
		req.Header.Set(securityToken, s.token)
	}

	canonHeaders, signedHeaders := canonicalHeaders(req)

	var (
		buf bytes.Buffer
		sum hash.Hash = sha256.New()
	)

	// Create the canonical request.
	buf.WriteString(req.Method)
	buf.WriteByte('\n')
	buf.WriteString(canonicalURI(req.URL))
	buf.WriteByte('\n')
	buf.WriteString(canonicalQueryString(req.URL))
	buf.WriteByte('\n')
	buf.WriteString(canonHeaders)
	buf.WriteByte('\n')
	buf.WriteString(signedHeaders)
	buf.WriteByte('\n')
	buf.WriteString(bodyDigest)
	sum.Write(buf.Bytes())
	creq := buf.String()
	buf.Reset()

	// Create the string to sign.
	buf.WriteString("AWS4-HMAC-SHA256")
	buf.WriteByte('\n')
	buf.WriteString(reqTime.Format(TimeFormat))
	buf.WriteByte('\n')
	buf.WriteString(strings.Join(s.scope[1:], "/"))
	buf.WriteByte('\n')
	fmt.Fprintf(&buf, "%x", sum.Sum(nil))
	sts := buf.String()

	// Sign the string to sign.
	sum = hmac.New(sha256.New, s.key[:])
	sum.Write(buf.Bytes())
	buf.Reset()

	buf.WriteString("AWS4-HMAC-SHA256")
	buf.WriteString(" Credential=")
	buf.WriteString(strings.Join(s.scope, "/"))
	buf.WriteString(", SignedHeaders=")
	buf.WriteString(signedHeaders)
	buf.WriteString(", Signature=")
	fmt.Fprintf(&buf, "%x", sum.Sum(nil))
	req.Header.Set("Authorization", buf.String())

	return creq, sts, nil
}

func ensureDate(h http.Header) (time.Time, error) {
	if text := h.Get(DateHeader); text != "" {
		return time.Parse(TimeFormat, text)
	} else if text := h.Get("date"); text != "" {
		return http.ParseTime(text)
	}
	now := time.Now().UTC()
	h.Set(DateHeader, now.Format(TimeFormat))
	return now, nil
}

// nilSum is used as bodyDigest when req.Body is nil or http.NoBody.
const nilSum = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// digestBody hashes req.Body using SHA256. If req.Body does not implement
// Payload, it is replaced with a memory buffer. digestBody returns the
// hex-encoded hash and any error that occured.
func digestBody(req *http.Request) (string, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return nilSum, nil
	}
	if p, ok := req.Body.(Payload); ok {
		return HashPayload(p)
	}
	h := sha256.New()
	b := new(bytes.Buffer)
	tr := io.TeeReader(req.Body, b)
	if _, err := io.Copy(h, tr); err != nil {
		return "", err
	}
	req.Body = ioutil.NopCloser(b)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// canonicalHeaders returns the canonical and signed headers.
func canonicalHeaders(req *http.Request) (string, string) {
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	c := []string{"host:" + strings.ToLower(host)}
	s := []string{"host"}

	// trim removes excess white space before and after s and converts
	// sequential spaces to a single space.
	trim := func(s string) string {
		fields := strings.Fields(strings.Trim(s, " "))
		return strings.Join(fields, " ")
	}

	for k, vv := range req.Header {
		vv2 := make([]string, len(vv))
		for i := range vv {
			vv2[i] = trim(vv[i])
		}

		k = strings.ToLower(k)
		c = append(c, k+":"+strings.Join(vv2, ","))
		s = append(s, k)
	}

	sort.Strings(c)
	sort.Strings(s)
	return strings.Join(c, "\n") + "\n", strings.Join(s, ";")
}

// canonicalURI returns the canonical URI for the given url. This is the
// URI-encoded version of the absolute path componen of the URI; everything
// from the HTTP Host header to the question mark character that begins the
// query string parameters.
func canonicalURI(u *url.URL) string {
	uri := u.RequestURI()
	if u.RawQuery != "" {
		uri = uri[:len(uri)-len(u.RawQuery)-1]
	}
	slash := strings.HasSuffix(uri, "/")
	uri = path.Clean(uri)
	if uri[len(uri)-1] != '/' && slash {
		uri += "/"
	}
	return uri
}

// canonicalQueryString returns the canonical query string for the given url.
// If the url does not include a query string, empty string is returned.
func canonicalQueryString(u *url.URL) string {
	var c []string

	escape := func(s string) string {
		// Go encodes space as '+' but AWS wants '%20'.
		return strings.Replace(url.QueryEscape(s), "+", "%20", -1)
	}

	for k, vv := range u.Query() {
		k = escape(k)
		for _, v := range vv {
			if v != "" {
				v = escape(v)
			}
			c = append(c, k+"="+v)
		}
	}
	sort.Strings(c)
	return strings.Join(c, "&")
}
