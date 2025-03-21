package goauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/gofiber/fiber/v2/log"
	"golang.org/x/oauth2"
	"net/http"
	"time"
)

const SessionCookie = "go-auth_session"
const CsrfCookie = "go-auth_csrf"

type Auth struct {
	basePath  string
	adapter   Adapter
	providers map[string]Provider
	options   AuthOptions

	stateSecret string
}

func NewAuth(basePath string, adapter Adapter, providers []Provider, options ...AuthOptions) *Auth {
	if len(options) > 1 {
		panic("more than one AuthOptions entries provided")
	}

	providerMap := make(map[string]Provider)
	for _, provider := range providers {
		if _, ok := providerMap[provider.ID()]; ok {
			panic(fmt.Sprintf("Provider with ID '%s' already registered", provider.ID()))
		}

		providerMap[provider.ID()] = provider
	}

	var authOptions AuthOptions
	if len(options) == 1 {
		authOptions = options[0]
	}

	return &Auth{
		basePath:    basePath,
		adapter:     adapter,
		stateSecret: oauth2.GenerateVerifier(),
		providers:   providerMap,
		options:     authOptions.withDefaults(),
	}
}

// Adapter returns the used database adapter, which can be used to remove sessions, etc.
func (a *Auth) Adapter() Adapter {
	return a.adapter
}

func (a *Auth) BasePath() string {
	return a.basePath
}

func (a *Auth) Handlers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch path := parsePath(r.URL.Path, a.basePath).(type) {
		case csrf:
			a.csrfHandler(w, r)
		case provider:
			a.providerHandler(path, w, r)
		case callback:
			a.providerCallbackHandler(path, w, r)
		case providers:
			a.providersHandler(w, r)
		case signOut:
			a.signOutHandler(w, r)
		case notFound:
			w.WriteHeader(http.StatusNotFound)
		case unmatched:
			next.ServeHTTP(w, r)
		}
	})
}

// SignOut signs out a user based on the value of the sessionId found in the request's cookies.
// Method **does not** send any status codes on fail, instead returning the encountered error.
// Not CSRF-protected.
func (a *Auth) SignOut(w http.ResponseWriter, r *http.Request) error {
	cookie, err := r.Cookie(SessionCookie)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return nil
		}
		return err
	}

	if err := a.adapter.RemoveSession(cookie.Value); err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Path:     "/",
		Value:    "",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(0, 0),
	})

	return nil
}

func (a *Auth) Authenticate(r *http.Request) (string, bool, error) {
	cookie, err := r.Cookie(SessionCookie)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return "", false, nil
		}

		return "", false, err
	}

	return a.AuthenticateSession(cookie.Value)
}

func (a *Auth) AuthenticateSession(sessionId string) (string, bool, error) {
	userId, expiresAt, err := a.adapter.GetSession(sessionId)
	if err != nil {
		return "", false, err
	}

	if expiresAt.Before(time.Now()) {
		_ = a.adapter.RemoveSession(sessionId)

		return "", false, errors.New("session expired")
	}

	return userId, true, nil
}

func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, authenticated, err := a.Authenticate(r)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if !authenticated {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (a *Auth) signInOAuth(provider OAuthProvider, userDetails *OAuthUserDetails) (string, error) {
	accountId, accountExists, err := a.adapter.GetAccountId(provider.ID(), userDetails.ProviderAccountId)
	if err != nil {
		return "", err
	}

	var userId string

	// An account is created using the unique combination of provider ID and provider account ID,
	// the account itself is in relation with a user entry uniquely identified with an email.
	// If user changes their email (on the OAuth provider side) the said change is not reflected
	// here as we default to checking whether the account already exists given its key pair.
	if !accountExists {
		log.Debugf("account for details (%s, %s) does not exist, creating new entry", provider.ID(), userDetails.ProviderAccountId)

		var userExists bool
		userId, userExists, err = a.adapter.GetUserIdByEmail(userDetails.Email)
		if err != nil {
			return "", err
		}

		if !userExists {
			log.Debugf("user with email %s does not exist, creating new entry", userDetails.Email)

			userId, err = a.adapter.CreateUser(userDetails.Email, userDetails.Username, userDetails.AvatarUrl)
			if err != nil {
				return "", err
			}
		}

		log.Debugf("user with email %s exists, id: %s", userDetails.Email, userId)

		accountId, err = a.adapter.CreateAccount(userId, provider.ID(), userDetails.ProviderAccountId)
		if err != nil {
			return "", err
		}
	} else {
		userId, err = a.adapter.GetConnectedUserId(accountId)
		if err != nil {
			return "", err
		}
	}

	log.Debugf("account for details (%s, %s) exists, id: %s", provider.ID(), userDetails.ProviderAccountId, accountId)

	return userId, nil
}

// csrfCookie sets a CSRF cookie with the generated random string as value.
// Returns the random string and its hashed representation (using a secret).
func (a *Auth) csrfCookie(w http.ResponseWriter) (string, string) {
	verifier := oauth2.GenerateVerifier()
	hash := generateHMAC(verifier, a.stateSecret)

	http.SetCookie(w, &http.Cookie{
		Name:     CsrfCookie,
		Value:    verifier,
		Path:     "/",
		Secure:   a.options.CookieSecure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	return verifier, hash
}

func generateHMAC(data, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(data))

	return base64.URLEncoding.EncodeToString(h.Sum(nil))
}
