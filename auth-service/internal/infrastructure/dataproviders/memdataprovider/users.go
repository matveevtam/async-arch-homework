package memdataprovider

import (
	"errors"
	"slices"
	"sync"

	"github.com/matveevtam/async-arch-homework/auth-service/internal/domain"
	"github.com/matveevtam/async-arch-homework/auth-service/internal/usecases/repositories"
	"github.com/rs/zerolog"
)

type InMemoryUserRepository struct {
	mutex  *sync.RWMutex
	users  []repositories.DBUser
	nextID int
	logger zerolog.Logger
}

func NewInMemoryUserRepository(logger zerolog.Logger) *InMemoryUserRepository {
	result := &InMemoryUserRepository{
		mutex:  &sync.RWMutex{},
		users:  make([]repositories.DBUser, 0),
		nextID: 0,
		logger: logger,
	}
	return result
}

func (r *InMemoryUserRepository) List() ([]repositories.DBUser, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	r.logger.Debug().Any("users", r.users).Msg("List() users")

	result := make([]repositories.DBUser, len(r.users))
	copy(result, r.users)
	return result, nil
}

func (r *InMemoryUserRepository) GetByPublicID(publicID domain.UserPublicID) (repositories.DBUser, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	i := slices.IndexFunc(r.users, func(u repositories.DBUser) bool {
		return u.PublicID == publicID
	})
	if i < 0 {
		return repositories.DBUser{}, repositories.ErrDBItemNotFound
	}
	return r.users[i], nil
}

func (r *InMemoryUserRepository) GetByEmail(email string) (repositories.DBUser, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	i := slices.IndexFunc(r.users, func(u repositories.DBUser) bool { return u.Email == email })
	if i < 0 {
		return repositories.DBUser{}, repositories.ErrDBItemNotFound
	}
	return r.users[i], nil
}

func (r *InMemoryUserRepository) EmailExists(email string) (bool, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	i := slices.IndexFunc(r.users, func(u repositories.DBUser) bool { return u.Email == email })
	return i >= 0, nil
}

func (r *InMemoryUserRepository) EmailBelongsToOther(email string, publicID domain.UserPublicID) (bool, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	i := slices.IndexFunc(r.users, func(u repositories.DBUser) bool { return u.Email == email })
	if i < 0 {
		return false, nil
	}
	return r.users[i].PublicID != publicID, nil
}

func (r *InMemoryUserRepository) Save(user domain.User) (repositories.DBUser, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if i := slices.IndexFunc(r.users, func(u repositories.DBUser) bool { return u.Email == user.Email }); i >= 0 {
		return repositories.DBUser{}, errors.New("user with such email already exists")
	}
	if i := slices.IndexFunc(r.users, func(u repositories.DBUser) bool { return u.PublicID == user.PublicID }); i >= 0 {
		return repositories.DBUser{}, errors.New("user with such public ID already exists")
	}

	dbUser := repositories.DBUser{
		ID:   r.nextID,
		User: user,
	}
	r.nextID += 1
	r.users = append(r.users, dbUser)
	return dbUser, nil
}

func (r *InMemoryUserRepository) Update(req repositories.DBUserUpdateRequest) (repositories.DBUser, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if req.Email != nil {
		if i := slices.IndexFunc(r.users, func(u repositories.DBUser) bool { return u.Email == *req.Email }); i >= 0 {
			return repositories.DBUser{}, errors.New("user with such email already exists")
		}
	}

	i := slices.IndexFunc(r.users, func(u repositories.DBUser) bool { return u.PublicID == req.PublicID })
	if i < 0 {
		return repositories.DBUser{}, repositories.ErrDBItemNotFound
	}
	dbUser := r.users[i]
	if req.Name != nil {
		dbUser.Name = *req.Name
	}
	if req.Email != nil {
		dbUser.Email = *req.Email
	}
	if req.Role != nil {
		dbUser.Role = *req.Role
	}
	r.users[i] = dbUser

	return dbUser, nil
}
