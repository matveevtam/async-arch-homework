package usecases

import (
	"github.com/google/uuid"
	"github.com/matveevtam/async-arch-homework/auth-service/internal/domain"
	"github.com/rs/zerolog"
)

type UserCheckAuthUseCase struct {
	secretKey []byte
	logger    zerolog.Logger
}

func NewUserCheckAuthUseCase(secretKey []byte, logger zerolog.Logger) UserCheckAuthUseCase {
	return UserCheckAuthUseCase{
		secretKey: secretKey,
		logger:    logger,
	}
}

type UserCheckAuthRequest struct {
	Token domain.UserToken
}

type UserCheckAuthResponse struct {
	UserAuthOK   bool
	UserPublicID domain.UserPublicID
	UserRole     domain.UserRole
}

func (uc UserCheckAuthUseCase) CheckUserAuth(r UserCheckAuthRequest) (resp UserCheckAuthResponse) {
	var err error

	claims, err := parseUserToken(r.Token, uc.secretKey)
	if err != nil {
		uc.logger.Info().Err(err).Msg("CheckUserAuth: user token invalid")
		resp.UserAuthOK = false
		return
	}
	publicID, err := uuid.Parse(claims.Subject)
	if err != nil {
		uc.logger.Info().Err(err).Msg("CheckUserAuth: user public ID invalid")
		return
	}
	resp.UserAuthOK = true
	resp.UserPublicID = domain.UserPublicID(publicID)
	resp.UserRole = claims.Role

	return
}
