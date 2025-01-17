package goauth

import (
	"golang.org/x/oauth2"
	"net/http"
)

type Provider interface {
	ID() string
	Info() any
}

type OAuthProvider interface {
	Provider

	Config() *oauth2.Config
	FetchUserData(client *http.Client) (OAuthUserDetails, error)
}

type OAuthUserDetails struct {
	ProviderAccountId string  `json:"provider_account_id"`
	Email             string  `json:"email"`
	Username          string  `json:"username"`
	AvatarUrl         *string `json:"avatar_url"`

	AccessToken  *string `json:"access_token"`
	RefreshToken *string `json:"refresh_token"`
}
