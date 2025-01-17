package providers

import (
	"encoding/json"
	"errors"
	"fmt"
	goauth "github.com/TeraWattHour/go-auth"
	"golang.org/x/oauth2"
	"net/http"
	"time"
)

func Github(clientId string, clientSecret string) *GithubConfig {
	return &GithubConfig{
		config: &oauth2.Config{
			ClientID:     clientId,
			ClientSecret: clientSecret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://github.com/login/oauth/authorize",
				TokenURL: "https://github.com/login/oauth/access_token",
			},
			Scopes: []string{"read:user", "user:email"},
		},
	}
}

type GithubConfig struct {
	config *oauth2.Config
}

func (c *GithubConfig) ID() string {
	return "github"
}

func (c *GithubConfig) Info() any {
	return map[string]any{
		"id":   c.ID(),
		"name": "GitHub",
	}
}

func (c *GithubConfig) Config() *oauth2.Config {
	return c.config
}

func (c *GithubConfig) FetchUserDetails(client *http.Client) (*goauth.OAuthUserDetails, error) {
	var user GithubUser
	if err := c.fetch(client, "GET", "https://api.github.com/user", &user); err != nil {
		return nil, err
	}

	email, err := c.fetchUserEmail(client)
	if err != nil {
		return nil, err
	}

	return &goauth.OAuthUserDetails{
		ProviderAccountId: fmt.Sprintf("%d", user.Id),
		Email:             email,
		Username:          user.Login,
		AvatarUrl:         &user.AvatarUrl,
	}, nil
}

func (c *GithubConfig) fetchUserEmail(client *http.Client) (string, error) {
	var emails []GithubEmail

	if err := c.fetch(client, "GET", "https://api.github.com/user/emails", &emails); err != nil {
		return "", err
	}

	for _, email := range emails {
		if email.Primary && email.Verified {
			return email.Email, nil
		}
	}

	return "", errors.New("no primary verified email found")
}

func (c *GithubConfig) fetch(client *http.Client, method string, url string, output any) error {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Accept", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("request failed with status code %d", res.StatusCode)
	}

	if err := json.NewDecoder(res.Body).Decode(output); err != nil {
		return err
	}

	return nil
}

type GithubExchangeInfo struct {
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
	TokenType   string `json:"token_type"`
}

type GithubEmail struct {
	Email      string `json:"email"`
	Primary    bool   `json:"primary"`
	Verified   bool   `json:"verified"`
	Visibility string `json:"visibility"`
}

type GithubUser struct {
	Login                   string    `json:"login"`
	Id                      int       `json:"id"`
	NodeId                  string    `json:"node_id"`
	AvatarUrl               string    `json:"avatar_url"`
	GravatarId              string    `json:"gravatar_id"`
	Url                     string    `json:"url"`
	HtmlUrl                 string    `json:"html_url"`
	FollowersUrl            string    `json:"followers_url"`
	FollowingUrl            string    `json:"following_url"`
	GistsUrl                string    `json:"gists_url"`
	StarredUrl              string    `json:"starred_url"`
	SubscriptionsUrl        string    `json:"subscriptions_url"`
	OrganizationsUrl        string    `json:"organizations_url"`
	ReposUrl                string    `json:"repos_url"`
	EventsUrl               string    `json:"events_url"`
	ReceivedEventsUrl       string    `json:"received_events_url"`
	Type                    string    `json:"type"`
	UserViewType            string    `json:"user_view_type"`
	SiteAdmin               bool      `json:"site_admin"`
	Name                    any       `json:"name"`
	Company                 any       `json:"company"`
	Blog                    string    `json:"blog"`
	Location                any       `json:"location"`
	Email                   any       `json:"email"`
	Hireable                any       `json:"hireable"`
	Bio                     any       `json:"bio"`
	TwitterUsername         any       `json:"twitter_username"`
	NotificationEmail       any       `json:"notification_email"`
	PublicRepos             int       `json:"public_repos"`
	PublicGists             int       `json:"public_gists"`
	Followers               int       `json:"followers"`
	Following               int       `json:"following"`
	CreatedAt               time.Time `json:"created_at"`
	UpdatedAt               time.Time `json:"updated_at"`
	PrivateGists            int       `json:"private_gists"`
	TotalPrivateRepos       int       `json:"total_private_repos"`
	OwnedPrivateRepos       int       `json:"owned_private_repos"`
	DiskUsage               int       `json:"disk_usage"`
	Collaborators           int       `json:"collaborators"`
	TwoFactorAuthentication bool      `json:"two_factor_authentication"`
	Plan                    struct {
		Name          string `json:"name"`
		Space         int    `json:"space"`
		Collaborators int    `json:"collaborators"`
		PrivateRepos  int    `json:"private_repos"`
	} `json:"plan"`
}
