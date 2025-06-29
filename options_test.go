package goauth

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOptionsWithDefaultsMinimal(t *testing.T) {
	opts := AuthOptions{
		SessionCookieName: "",
		CookieSecure:      true,
	}.withDefaults()

	assert.Equal(t, sessionCookie, opts.SessionCookieName)
	assert.Equal(t, true, opts.CookieSecure)
	assert.Equal(t, http.SameSiteLaxMode, opts.CookieSameSite)
}

func TestOptionsWithDefaultsFull(t *testing.T) {
	opts := AuthOptions{
		SessionCookieName: "foo",
		CookieSecure:      false,
		CookieSameSite:    http.SameSiteDefaultMode,
		CookieDomain:      "foo.bar.com",
	}.withDefaults()

	assert.Equal(t, csrfCookie, opts.CsrfCookieName)
	assert.Equal(t, "foo", opts.SessionCookieName)
	assert.Equal(t, false, opts.CookieSecure)
	assert.Equal(t, http.SameSiteDefaultMode, opts.CookieSameSite)
	assert.Equal(t, "foo.bar.com", opts.CookieDomain)
}
