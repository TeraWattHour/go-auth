package goauth

import (
	"context"
	"encoding/json"
	"github.com/gofiber/fiber/v2/log"
	"golang.org/x/oauth2"
	"net/http"
	"time"
)

func (a *Auth) providerCallbackHandler(path callback, w http.ResponseWriter, r *http.Request) {
	defer http.SetCookie(w, &http.Cookie{
		Name:    CsrfCookie,
		Value:   "",
		Path:    "/",
		Expires: time.Unix(0, 0),
	})

	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	provider, ok := a.providers[path.providerId].(OAuthProvider)
	if !ok {
		http.NotFound(w, r)
		return
	}

	sessionVerifierCookie, err := r.Cookie(CsrfCookie)
	if err != nil {
		http.Error(w, "CSRF token must be present", http.StatusBadRequest)
		return
	}

	if generateHMAC(sessionVerifierCookie.Value, a.stateSecret) != r.URL.Query().Get("state") {
		http.Error(w, "Malformed CSRF token", http.StatusBadRequest)
		return
	}

	switch provider := provider.(type) {
	case OAuthProvider:
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "No code provided", http.StatusBadRequest)
			return
		}

		token, err := provider.Config().Exchange(context.Background(), code, oauth2.VerifierOption(sessionVerifierCookie.Value))
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		client := provider.Config().Client(context.Background(), token)

		userDetails, err := provider.FetchUserData(client)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		userId, err := a.signInOAuth(provider, userDetails)
		if err != nil {
			log.Error("error while processing OAuth callback", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		sessionId, expiresAt, err := a.adapter.CreateSession(userId)
		if err != nil {
			log.Error("error while creating session", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     SessionCookie,
			Value:    sessionId,
			Path:     "/",
			Expires:  expiresAt,
			HttpOnly: true,
			Secure:   a.options.CookieSecure,
			SameSite: http.SameSiteLaxMode,
		})

		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	default:
		http.NotFound(w, r)
	}
}

func (a *Auth) providersHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	by, err := json.Marshal(a.ProviderInfo())
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(by)
}

func (a *Auth) providerHandler(path provider, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if provider, ok := a.providers[path.providerId].(OAuthProvider); ok {
		verifier, hash, err := a.applyState(w)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		url := provider.Config().AuthCodeURL(hash, oauth2.AccessTypeOffline, oauth2.S256ChallengeOption(verifier))
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	} else {
		http.NotFound(w, r)
	}
}

func (a *Auth) signOutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if err := a.SignOut(w, r); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}
