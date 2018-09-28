package aws

import (
	"context"
	"os"
)

// credentials holds the signing keys for a Session.
type credentials struct {
	KeyID        string
	SecretKey    string
	SessionToken string
}

type credGetter interface {
	Get(context.Context, *credentials) error
}

var providers = []credGetter{
	environ{},
}

func (c *credentials) Init(ctx context.Context) error {
	for i := 0; c.KeyID == "" && c.SecretKey == "" && i < len(providers); i++ {
		if err := providers[i].Get(ctx, c); err != nil {
			return err
		}
	}
	if c.KeyID == "" || c.SecretKey == "" {
		return ErrNoCredentials
	}
	return nil
}

// environ tries to load credentials from environment variables.
type environ struct{}

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

func (e environ) Get(ctx context.Context, cred *credentials) error {
	maybeLoadFromEnv(&cred.KeyID, accessKeyEnvVars)
	maybeLoadFromEnv(&cred.SecretKey, secretKeyEnvVars)
	maybeLoadFromEnv(&cred.SessionToken, sessionTokenEnvVars)
	return nil
}

func maybeLoadFromEnv(s *string, vars []string) {
	vs := *s
	for i := 0; i < len(vars) && vs == ""; i++ {
		vs = os.Getenv(vars[i])
	}
	*s = vs
}
