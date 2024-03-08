package memdataprovider

import (
	"errors"
	"slices"
	"sync"

	"github.com/matveevtam/async-arch-homework/auth-service/internal/domain"
	"github.com/matveevtam/async-arch-homework/auth-service/internal/usecases/repositories"
)

type InMemoryServiceRepository struct {
	mutex    *sync.RWMutex
	services []repositories.DBService
}

func NewInMemoryServiceRepository() *InMemoryServiceRepository {
	return &InMemoryServiceRepository{
		mutex:    &sync.RWMutex{},
		services: make([]repositories.DBService, 0),
	}
}

func (r *InMemoryServiceRepository) List() ([]repositories.DBService, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	result := make([]repositories.DBService, len(r.services))
	copy(result, r.services)
	return result, nil
}

func (r *InMemoryServiceRepository) GetByName(name string) (repositories.DBService, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	i := slices.IndexFunc(r.services, func(s repositories.DBService) bool { return s.Name == name })
	if i < 0 {
		return repositories.DBService{}, repositories.ErrDBItemNotFound
	}
	return r.services[i], nil
}

func (r *InMemoryServiceRepository) NameExists(name string) (bool, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	i := slices.IndexFunc(r.services, func(s repositories.DBService) bool { return s.Name == name })
	return i >= 0, nil
}

func (r *InMemoryServiceRepository) Save(service domain.Service) (repositories.DBService, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	i := slices.IndexFunc(r.services, func(s repositories.DBService) bool { return s.Name == service.Name })
	if i >= 0 {
		return repositories.DBService{}, errors.New("service name already exists in DB")
	}

	dbService := repositories.DBService{Service: service}
	r.services = append(r.services, dbService)
	return dbService, nil
}
