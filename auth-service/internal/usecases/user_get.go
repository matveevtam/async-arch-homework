package usecases

import (
	"errors"
	"slices"

	"github.com/matveevtam/async-arch-homework/auth-service/internal/domain"
	"github.com/matveevtam/async-arch-homework/auth-service/internal/usecases/repositories"
	"github.com/rs/zerolog"
)

var (
	ErrUserGetNotAllowed = errors.New("user with such role is not allowed to perform this action")
	ErrUserGetNotFound   = errors.New("user not found")
)

type UserGetUseCase struct {
	userRepository repositories.UserRepository
	logger         zerolog.Logger
}

func NewUserGetUseCase(userRepository repositories.UserRepository, logger zerolog.Logger) UserGetUseCase {
	return UserGetUseCase{
		userRepository: userRepository,
		logger:         logger,
	}
}

type GetUserByPublicIDRequest struct {
	ActorRole     domain.UserRole
	ActorPublicID domain.UserPublicID
	UserPublicID  domain.UserPublicID
}

type ListUsersRequest struct {
	ActorRole domain.UserRole
}

var (
	getUserAllowedRoles = []domain.UserRole{domain.RoleManager, domain.RoleAdmin, domain.RoleBoss}
)

func (uc UserGetUseCase) GetUserByPublicID(r GetUserByPublicIDRequest) (domain.User, error) {
	if r.ActorPublicID != r.UserPublicID {
		if i := slices.Index(getUserAllowedRoles, r.ActorRole); i < 0 {
			return domain.User{}, ErrUserGetNotAllowed
		}
	}

	dbUser, err := uc.userRepository.GetByPublicID(r.UserPublicID)
	if err == repositories.ErrDBItemNotFound {
		return domain.User{}, ErrUserGetNotFound
	}
	user := dbUser.User
	return user, err
}

func (uc UserGetUseCase) ListUsers(r ListUsersRequest) ([]domain.User, error) {
	if i := slices.Index(getUserAllowedRoles, r.ActorRole); i < 0 {
		return nil, ErrUserGetNotAllowed
	}

	dbUsers, err := uc.userRepository.List()
	if err != nil {
		return nil, err
	}

	users := make([]domain.User, len(dbUsers))
	for i := range dbUsers {
		users[i] = dbUsers[i].User
	}
	return users, err
}
