package goauth

import "time"

type Adapter interface {
	GetUserIdByEmail(email string) (string, bool, error)
	GetConnectedUserId(accountId string) (string, error)
	GetAccountId(providerId string, providerAccountId string) (string, bool, error)
	GetSession(sessionId string) (string, time.Time, error)
	RemoveSession(sessionId string) error

	CreateSession(userId string) (string, time.Time, error)
	CreateUser(email string, name string, avatar *string) (string, error)
	CreateAccount(userId string, providerId string, providerAccountId string) (string, error)
}
