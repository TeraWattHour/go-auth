package providers

import (
	"encoding/json"
	"fmt"
	"github.com/TeraWattHour/go-auth"
	"golang.org/x/oauth2"
	"net/http"
)

func Google(clientId string, clientSecret string, redirectURL string) *GoogleConfig {
	return &GoogleConfig{
		config: &oauth2.Config{
			ClientID:     clientId,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://accounts.google.com/o/oauth2/v2/auth",
				TokenURL: "https://oauth2.googleapis.com/token",
			},
			Scopes: []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
		},
	}
}

type GoogleConfig struct {
	config *oauth2.Config
}

func (c *GoogleConfig) ID() string {
	return "google"
}

func (c *GoogleConfig) Config() *oauth2.Config {
	return c.config
}

func (c *GoogleConfig) FetchUserData(client *http.Client) (*goauth.OAuthUserDetails, error) {
	res, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	details := GoogleUser{}
	if err := json.NewDecoder(res.Body).Decode(&details); err != nil {
		return nil, err
	}

	if !details.EmailVerified {
		return nil, fmt.Errorf("email not verified")
	}

	return &goauth.OAuthUserDetails{
		ProviderAccountId: details.Sub,
		Email:             details.Email,
		Username:          details.Name,
		AvatarUrl:         &details.Picture,
	}, nil
}

type GoogleUser struct {
	Sub           string
	Email         string
	EmailVerified bool `json:"email_verified"`
	Name          string
	Picture       string
}
