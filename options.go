package goauth

import "net/http"

type AuthOptions struct {
	SessionCookieName string
	CsrfCookieName    string

	CookieSecure   bool
	CookieDomain   string
	CookieSameSite http.SameSite

	SuccessRedirectUrl string
	FailureRedirectUrl string
}

const sessionCookie = "go-auth_session"
const csrfCookie = "go-auth_csrf"

func (left AuthOptions) withDefaults() AuthOptions {

	// SessionCookieName
	sessionCookieName := left.SessionCookieName
	if len(sessionCookieName) == 0 {
		sessionCookieName = sessionCookie
	}

	// CsrfCookieName
	csrfCookieName := left.CsrfCookieName
	if len(csrfCookieName) == 0 {
		csrfCookieName = csrfCookie
	}

	// CookieSameSite
	sameSite := left.CookieSameSite
	if sameSite == 0 {
		sameSite = http.SameSiteLaxMode
	}

	defaults := AuthOptions{
		SessionCookieName: sessionCookieName,
		CsrfCookieName:    csrfCookieName,

		CookieSecure:   left.CookieSecure,
		CookieDomain:   left.CookieDomain,
		CookieSameSite: sameSite,

		SuccessRedirectUrl: left.SuccessRedirectUrl,
		FailureRedirectUrl: left.FailureRedirectUrl,
	}

	return defaults
}
