// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"golang.org/x/oauth2"
	"net/url"

	"crypto/rand"
	"crypto/sha256"
	b64 "encoding/base64"
	"io"
)

type ProviderTwitter struct {
	*ProviderGenericOIDC
}

func NewProviderTwitter(
	config *Configuration,
	reg dependencies,
) *ProviderTwitter {
	return &ProviderTwitter{
		ProviderGenericOIDC: &ProviderGenericOIDC{
			config: config,
			reg:    reg,
		},
	}
}

func (g *ProviderTwitter) Config() *Configuration {
	return g.config
}

func (g *ProviderTwitter) oauth2(ctx context.Context) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     g.config.ClientID,
		ClientSecret: g.config.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL: "https://twitter.com/i/oauth2/authorize",
            TokenURL: "https://api.twitter.com/2/oauth2/token",
			AuthStyle: oauth2.AuthStyleInHeader,
		},
		Scopes:      g.config.Scope,
		RedirectURL: g.config.Redir(g.reg.Config().OIDCRedirectURIBase(ctx)),
	}
}

func (g *ProviderTwitter) OAuth2(ctx context.Context) (*oauth2.Config, error) {
	return g.oauth2(ctx), nil
}

func (g *ProviderTwitter) AuthCodeURLOptions(r ider) []oauth2.AuthCodeOption {
	return []oauth2.AuthCodeOption{}
}

func (g *ProviderTwitter) Challenge(ctx context.Context) (ProviderChallenge, error) {
	verifier := SecureRandomBase64Encoded(32)
	challenge := PkCEChallengeWithSHA256(verifier)
	return ProviderChallenge{
		Challenge: challenge,
		//TODO: If challenge method is plain, then pass challenge as verifier 
		ChallengeMethod: "s256",
		Verifier: verifier,
	}, nil
}

func PkCEChallengeWithSHA256(verifier string) string {
	h := sha256.New()
	h.Write([]byte(verifier))
	return b64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func randStringBytes(n int) string {
	b := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, b[:])
	if err != nil {
		return ""
	}
	return b64.RawURLEncoding.EncodeToString(b[:])
}

func (g *ProviderTwitter) Claims(ctx context.Context, exchange *oauth2.Token, query url.Values) (*Claims, error) {
	claims := &Claims{
		Subject:   "user:123",
		Issuer:    "https://api.twitter.com/2/oauth2/token",
		Name:      "test",
		Nickname:  "test",
		Email: 	   "test@gmail.com",
		EmailVerified: true,
	}

	rawClaims := make(map[string]interface{})

	claims.RawClaims = rawClaims

	return claims, nil
}

func SecureRandomBase64Encoded(entropyByte int) string {
	b := make([]byte, entropyByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(err)
	}
	return b64.RawURLEncoding.EncodeToString(b)
}