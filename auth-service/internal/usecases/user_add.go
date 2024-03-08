package usecases

import (
	"errors"
	"slices"

	"github.com/google/uuid"
	"github.com/matveevtam/async-arch-homework/auth-service/internal/domain"
	"github.com/matveevtam/async-arch-homework/auth-service/internal/usecases/repositories"
	"github.com/matveevtam/async-arch-homework/auth-service/internal/utils"
	"github.com/rs/zerolog"
)

var (
	ErrUserAddNotAllowed       = errors.New("user with such role is not allowed to perform this action")
	ErrUserAddPasswordTooShort = errors.New("password is too short")
	ErrUserAddEmailOccupied    = errors.New("email is already occupied")
)

type UserAddUseCase struct {
	userRepository  repositories.UserRepository
	eventRepository repositories.EventRepository
	logger          zerolog.Logger
}

func NewUserAddUseCase(userRepository repositories.UserRepository, eventRepository repositories.EventRepository, logger zerolog.Logger) UserAddUseCase {
	return UserAddUseCase{
		userRepository:  userRepository,
		eventRepository: eventRepository,
		logger:          logger,
	}
}

type AddUserRequest struct {
	ActorRole domain.UserRole
	Name      string
	Email     string
	Role      domain.UserRole
	Password  string
}

var addUserAllowedRoles = []domain.UserRole{domain.RoleManager, domain.RoleAdmin, domain.RoleBoss}

func (uc UserAddUseCase) AddUser(r AddUserRequest) (domain.User, error) {
	if i := slices.Index(addUserAllowedRoles, r.ActorRole); i < 0 {
		return domain.User{}, ErrUserAddNotAllowed
	}

	if len(r.Password) < 3 {
		return domain.User{}, ErrUserAddPasswordTooShort
	}
	if emailOccupied, err := uc.userRepository.EmailExists(r.Email); err != nil {
		return domain.User{}, err
	} else if emailOccupied {
		return domain.User{}, ErrUserAddEmailOccupied
	}

	publicID := domain.UserPublicID(uuid.New())
	passwordSalt := utils.RandString(16)
	passwordHash := calcPasswordHash(r.Password, passwordSalt)

	dbUser, err := uc.userRepository.Save(domain.User{
		PublicID:     publicID,
		Name:         r.Name,
		Email:        r.Email,
		Role:         r.Role,
		PasswordHash: passwordHash,
		PasswordSalt: passwordSalt,
	})
	user := dbUser.User

	event := repositories.UserAddedEvent{
		PublicID: user.PublicID,
		Name:     user.Name,
		Email:    user.Email,
		Role:     user.Role,
	}

	if eventErr := uc.eventRepository.SendUserAdded(event); eventErr != nil {
		uc.logger.
			Err(eventErr).
			Any("event", event).
			Msg("could not send UserAddedEvent")
	}
	return user, err
}
