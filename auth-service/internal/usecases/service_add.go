package usecases

import (
	"errors"
	"slices"

	"github.com/google/uuid"
	"github.com/matveevtam/async-arch-homework/auth-service/internal/domain"
	"github.com/matveevtam/async-arch-homework/auth-service/internal/usecases/repositories"
)

var (
	ErrServiceAddNotAllowed    = errors.New("user with such role is not allowed to perform this action")
	ErrServiceAddAlreadyExists = errors.New("service with such name already exists")
)

type ServiceAddUseCase struct {
	repository repositories.ServiceRepository
}

func NewServiceAddUseCase(repository repositories.ServiceRepository) ServiceAddUseCase {
	return ServiceAddUseCase{repository: repository}
}

type AddServiceRequest struct {
	ActorRole domain.UserRole
	Name      string
}

var addServiceAllowedRoles = []domain.UserRole{domain.RoleAdmin}

func (uc ServiceAddUseCase) AddService(r AddServiceRequest) (domain.Service, error) {
	if i := slices.Index(addServiceAllowedRoles, r.ActorRole); i < 0 {
		return domain.Service{}, ErrServiceAddNotAllowed
	}

	nameExists, err := uc.repository.NameExists(r.Name)
	if err != nil {
		return domain.Service{}, err
	}
	if nameExists {
		return domain.Service{}, ErrServiceAddAlreadyExists
	}

	secret := uuid.NewString()
	dbService, err := uc.repository.Save(domain.Service{Name: r.Name, Secret: secret})
	return dbService.Service, err
}
