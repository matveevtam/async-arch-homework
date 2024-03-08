package repositories

import (
	"github.com/matveevtam/async-arch-homework/auth-service/internal/domain"
)

type DBService struct {
	domain.Service
}

type ServiceRepository interface {
	List() ([]DBService, error)
	GetByName(string) (DBService, error)
	NameExists(string) (bool, error)
	Save(domain.Service) (DBService, error)
}
