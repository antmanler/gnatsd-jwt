package jwtauth

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/nats-io/gnatsd/server"
)

// JWTAuth implements server.Authentication interface
type JWTAuth struct {
	PublicKeys []KeyProvider
	logger     Logger
}

// static assert
var _ server.Authentication = (*JWTAuth)(nil)

type userModel struct {
	Subject     string              `json:"sub"`
	ExpiresAt   *int64              `json:"exp,omitempty"`
	User        string              `json:"user,omitempty"`
	Name        string              `json:"name,omitempty"`
	Permissions *server.Permissions `json:"permissions,omitempty"`
}

// Check returns true if connection is valid
func (auth *JWTAuth) Check(c server.ClientAuthentication) bool {
	if len(auth.PublicKeys) <= 0 {
		auth.Debugf("no public keys")
		return false
	}
	// retrive token
	opts := c.GetOpts()
	if opts == nil {
		return false
	}
	token, err := auth.verify(opts.Authorization)
	if err != nil {
		auth.Errorf("failed to auth token, %v", err)
		return false
	}
	claims, ok := token.Claims.(*userModel)
	if !ok {
		return true
	}
	var user server.User
	if claims.Subject != "" {
		user.Username = claims.Subject
	} else if claims.User != "" {
		user.Username = claims.User
	} else if claims.Name != "" {
		user.Username = claims.Name
	}
	if user.Username == "" {
		auth.Errorf("User name is required")
		return false
	}
	if claims.Permissions != nil {
		// check permissions
		if func() bool {
			for _, pubs := range claims.Permissions.Publish {
				if !server.IsValidSubject(pubs) {
					auth.Errorf("%v is invalid subject in Publish", pubs)
					return false
				}
			}
			for _, subs := range claims.Permissions.Subscribe {
				if !server.IsValidSubject(subs) {
					auth.Errorf("%v is invalid subject in Subscribe", subs)
					return false
				}
			}
			return true
		}() {
			user.Permissions = claims.Permissions
		}
	}
	auth.Debugf("Verified user %q, with perms %v", user.Username, user.Permissions != nil)
	c.RegisterUser(&user)
	return true
}

// verify will return a parsed token if it passes validation, or an
// error if any part of the token fails validation.  Possible errors include
// malformed tokens, unknown/unspecified signing algorithms, missing secret key,
// tokens that are not valid yet (i.e., 'nbf' field), tokens that are expired,
// and tokens that fail signature verification (forged)
func (auth *JWTAuth) verify(uToken string) (token *jwt.Token, err error) {
	if len(uToken) <= 0 {
		return nil, errors.New("token is empty")
	}

	for _, kp := range auth.PublicKeys {
		// Validate token
		token, err = jwt.ParseWithClaims(uToken, &userModel{}, func(t *jwt.Token) (interface{}, error) {
			pk, err := kp.PublicKey()
			if err != nil {
				return nil, err
			}
			switch pk.(type) {
			case *rsa.PublicKey:
				if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
					return nil, fmt.Errorf("expect token signed with RSA but got %v", token.Header["alg"])
				}
			case *ecdsa.PublicKey:
				if _, ok := t.Method.(*jwt.SigningMethodECDSA); !ok {
					return nil, fmt.Errorf("expect token signed with ECDSA but got %v", token.Header["alg"])
				}
			default:
				return nil, fmt.Errorf("only RSA & ECDSA are supported but got %v", token.Header["alg"])
			}
			return pk, nil
		})

		if err == nil {
			// break on first correctly validated token
			break
		}
	}

	if err != nil {
		token = nil
	}

	return
}

// Valid lets us use the user info as Claim for jwt-go.
// It checks the token expiry.
func (u userModel) Valid() error {
	if u.ExpiresAt == nil {
		return nil
	}
	if *u.ExpiresAt < jwt.TimeFunc().Unix() {
		return errors.New("token expired")
	}
	return nil
}
