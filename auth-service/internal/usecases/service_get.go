package usecases

import (
	"errors"
	"slices"

	"github.com/matveevtam/async-arch-homework/auth-service/internal/domain"
	"github.com/matveevtam/async-arch-homework/auth-service/internal/usecases/repositories"
	"github.com/rs/zerolog"
)

var (
	ErrServiceGetNotAllowed = errors.New("user with such role is not allowed to perform this action")
	ErrServiceGetNotFound   = errors.New("service not found")
)

type ServiceGetUseCase struct {
	serviceRepository repositories.ServiceRepository
	logger            zerolog.Logger
}

func NewServiceGetUseCase(serviceRepository repositories.ServiceRepository, logger zerolog.Logger) ServiceGetUseCase {
	return ServiceGetUseCase{
		serviceRepository: serviceRepository,
		logger:            logger,
	}
}

type ListServicesRequest struct {
	ActorRole domain.UserRole
}

var (
	getServiceAllowedRoles = []domain.UserRole{domain.RoleAdmin, domain.RoleBoss}
)

func (uc ServiceGetUseCase) ListServices(r ListServicesRequest) ([]domain.Service, error) {
	if i := slices.Index(getServiceAllowedRoles, r.ActorRole); i < 0 {
		return nil, ErrServiceGetNotAllowed
	}

	dbServices, err := uc.serviceRepository.List()
	if err != nil {
		return nil, err
	}

	services := make([]domain.Service, len(dbServices))
	for i := range dbServices {
		services[i] = dbServices[i].Service
	}
	return services, err
}
