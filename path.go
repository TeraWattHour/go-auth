package goauth

import "strings"

type notFound struct{}
type signOut struct{}
type providers struct{}
type unmatched struct{}
type provider struct {
	providerId string
}
type callback struct {
	providerId string
}

func parsePath(path, basePath string) any {
	if !strings.HasPrefix(path, basePath) {
		return unmatched{}
	}

	ownedPath := strings.TrimPrefix(strings.TrimPrefix(path, basePath), "/")
	parts := strings.Split(ownedPath, "/")

	if len(parts) == 2 && parts[1] == "callback" {
		return callback{parts[0]}
	}

	if len(parts) == 1 {
		switch parts[0] {
		case "providers":
			return providers{}
		case "sign-out":
			return signOut{}
		default:
			return provider{parts[0]}
		}
	}

	return notFound{}
}
