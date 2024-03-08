package usecases

import (
	"github.com/google/uuid"
	"github.com/matveevtam/async-arch-homework/auth-service/internal/domain"
	"github.com/rs/zerolog"
)

type ServiceCheckAuthUseCase struct {
	serviceSecretKey []byte
	userSecretKey    []byte
	logger           zerolog.Logger
}

func NewServiceCheckAuthUseCase(serviceSecretKey []byte, userSecretKey []byte, logger zerolog.Logger) ServiceCheckAuthUseCase {
	return ServiceCheckAuthUseCase{
		serviceSecretKey: serviceSecretKey,
		userSecretKey:    userSecretKey,
		logger:           logger,
	}
}

type ServiceCheckAuthRequest struct {
	SericeToken domain.ServiceToken
	UserToken   domain.UserToken
}

type ServiceCheckAuthResponse struct {
	IsServiceAuthOK bool
	ServiceName     string
	IsUserAuthOK    bool
	UserPublicID    domain.UserPublicID
	UserRole        domain.UserRole
}

func (uc ServiceCheckAuthUseCase) CheckServiceAuth(r ServiceCheckAuthRequest) (resp ServiceCheckAuthResponse) {
	var err error

	resp.ServiceName, err = parseServiceToken(r.SericeToken, uc.serviceSecretKey)
	if err != nil {
		uc.logger.Info().Err(err).Msg("CheckServiceAuth: service token invalid")
		resp.IsServiceAuthOK = false
		resp.IsUserAuthOK = false
		return
	}
	resp.IsServiceAuthOK = true

	userClaims, err := parseUserToken(r.UserToken, uc.userSecretKey)
	if err != nil {
		uc.logger.Info().Err(err).Msg("CheckServiceAuth: user token invalid")
		resp.IsUserAuthOK = false
		return
	}
	userPublicID, err := uuid.Parse(userClaims.Subject)
	if err != nil {
		uc.logger.Info().Err(err).Msg("CheckServiceAuth: user public ID invalid")
		resp.IsUserAuthOK = false
		return
	}
	resp.IsUserAuthOK = true
	resp.UserPublicID = domain.UserPublicID(userPublicID)
	resp.UserRole = userClaims.Role

	return
}
