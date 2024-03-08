package usecases

import (
	"crypto/sha256"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/matveevtam/async-arch-homework/auth-service/internal/domain"
)

func calcPasswordHash(password, passwordSalt string) string {
	h := sha256.New()
	h.Write([]byte(password))
	h.Write([]byte(passwordSalt))
	return string(h.Sum(nil))
}

type userClaims struct {
	jwt.RegisteredClaims
	Role domain.UserRole `json:"role"`
}

const (
	issuer              = "papug-auth-service"
	userTokenTimeout    = 24 * time.Hour
	serviceTokenTimeout = 1 * time.Hour
)

func makeUserToken(user domain.User, secretKey []byte) (domain.UserToken, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, userClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   user.PublicID.String(),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(userTokenTimeout)),
		},
		Role: user.Role,
	})

	tokenStr, err := token.SignedString(secretKey)

	return domain.UserToken(tokenStr), err
}

func parseUserToken(userToken domain.UserToken, secretKey []byte) (userClaims, error) {
	keyFunc := func(_ *jwt.Token) (interface{}, error) { return secretKey, nil }
	token, err := jwt.ParseWithClaims(
		string(userToken),
		&userClaims{},
		keyFunc,
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}),
		jwt.WithIssuer(issuer),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)
	if err != nil {
		return userClaims{}, err
	}
	claims, ok := token.Claims.(*userClaims)
	if !ok {
		return userClaims{}, errors.New("user claims are of unexpected type")
	}
	return *claims, nil
}

func makeServiceToken(service domain.Service, secretKey []byte) (domain.ServiceToken, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    issuer,
		Subject:   service.Name,
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(serviceTokenTimeout)),
	})

	tokenStr, err := token.SignedString(secretKey)

	return domain.ServiceToken(tokenStr), err
}

func parseServiceToken(serviceToken domain.ServiceToken, secretKey []byte) (string, error) {
	keyFunc := func(_ *jwt.Token) (interface{}, error) { return secretKey, nil }
	token, err := jwt.Parse(
		string(serviceToken),
		keyFunc,
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}),
		jwt.WithIssuer(issuer),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)
	if err != nil {
		return "", err
	}
	return token.Claims.GetIssuer()
}
