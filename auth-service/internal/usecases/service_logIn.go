package usecases

import (
	"errors"

	"github.com/matveevtam/async-arch-homework/auth-service/internal/domain"
	"github.com/matveevtam/async-arch-homework/auth-service/internal/usecases/repositories"
)

var (
	ErrServiceLogInNameNotFound    = errors.New("no service with such name")
	ErrServiceLogInIncorrectSecret = errors.New("service secret key is incorrect")
)

type ServiceLogInUseCase struct {
	repository repositories.ServiceRepository
	secretKey  []byte
}

func NewServiceLogInUseCase(repository repositories.ServiceRepository, secretKey []byte) ServiceLogInUseCase {
	return ServiceLogInUseCase{
		repository: repository,
		secretKey:  secretKey,
	}
}

type ServiceLogInRequest struct {
	Name   string
	Secret string
}

func (uc ServiceLogInUseCase) LogIn(r ServiceLogInRequest) (domain.ServiceToken, error) {
	dbService, err := uc.repository.GetByName(r.Name)
	if errors.Is(err, repositories.ErrDBItemNotFound) {
		return "", ErrServiceLogInNameNotFound
	}
	if err != nil {
		return "", err
	}
	service := dbService.Service

	if r.Secret != service.Secret {
		return "", ErrServiceLogInIncorrectSecret
	}

	token, err := makeServiceToken(service, uc.secretKey)

	return token, err
}
