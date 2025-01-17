package goauth

type AuthOptions struct {
	CookieSecure bool
}

func (left AuthOptions) withDefaults() AuthOptions {
	defaults := AuthOptions{
		CookieSecure: left.CookieSecure,
	}

	return defaults
}
