package goauth

import (
	"context"
	"encoding/json"
	"github.com/gofiber/fiber/v2/log"
	"golang.org/x/oauth2"
	"maps"
	"net/http"
	"slices"
	"time"
)

func (a *Auth) csrfHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	verifier := oauth2.GenerateVerifier()
	hash := generateHMAC(verifier, a.stateSecret)

	http.SetCookie(w, &http.Cookie{
		Name:     CsrfCookie,
		Value:    verifier,
		Path:     "/",
		Secure:   a.options.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		HttpOnly: true,
	})

	_, _ = w.Write([]byte(hash))
}

func (a *Auth) providerHandler(path provider, w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	provider, ok := a.providers[path.providerId].(OAuthProvider)
	if !ok {
		http.NotFound(w, r)
		return
	}

	verifier, hash, err := a.applyState(w)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	url := provider.Config().AuthCodeURL(hash, oauth2.AccessTypeOffline, oauth2.S256ChallengeOption(verifier))

	if r.Header.Get("X-NoRedirect") != "" {
		_, _ = w.Write([]byte(url))
	} else {
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	}
}

func (a *Auth) providerCallbackHandler(path callback, w http.ResponseWriter, r *http.Request) {
	defer removeCookie(CsrfCookie, w)

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
	if err != nil || generateHMAC(sessionVerifierCookie.Value, a.stateSecret) != r.URL.Query().Get("state") {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
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

	by, err := json.Marshal(slices.Collect(maps.Keys(a.providers)))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(by)
}

func (a *Auth) signOutHandler(w http.ResponseWriter, r *http.Request) {
	defer removeCookie(CsrfCookie, w)

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	csrfHash := r.Header.Get("X-Csrf-Token")
	csrfCookie, err := r.Cookie(CsrfCookie)
	if err != nil || generateHMAC(csrfCookie.Value, a.stateSecret) != csrfHash {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	if err := a.SignOut(w, r); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func removeCookie(name string, w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
	})
}
