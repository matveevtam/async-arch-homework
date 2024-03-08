package usecases

import (
	"errors"
	"slices"

	"github.com/matveevtam/async-arch-homework/auth-service/internal/domain"
	"github.com/matveevtam/async-arch-homework/auth-service/internal/usecases/repositories"
	"github.com/rs/zerolog"
)

var (
	ErrUserUpdateNotAllowed    = errors.New("user with such role is not allowed to perform this action")
	ErrUserUpdateEmailOccupied = errors.New("email is already occupied")
)

type UserUpdateUseCase struct {
	userRepository  repositories.UserRepository
	eventRepository repositories.EventRepository
	logger          zerolog.Logger
}

func NewUserUpdateUseCase(userRepository repositories.UserRepository, eventRepository repositories.EventRepository, logger zerolog.Logger) UserUpdateUseCase {
	return UserUpdateUseCase{
		userRepository:  userRepository,
		eventRepository: eventRepository,
		logger:          logger,
	}
}

type UserUpdateRequest struct {
	ActorRole domain.UserRole
	PublicID  domain.UserPublicID
	Name      *string
	Email     *string
	Role      *domain.UserRole
}

var updateUserAllowedRoles = []domain.UserRole{domain.RoleManager, domain.RoleAdmin, domain.RoleBoss}

func (uc UserUpdateUseCase) UpdateUser(r UserUpdateRequest) (domain.User, error) {
	if i := slices.Index(updateUserAllowedRoles, r.ActorRole); i < 0 {
		return domain.User{}, ErrUserUpdateNotAllowed
	}

	if r.Email != nil {
		emailOccupied, err := uc.userRepository.EmailBelongsToOther(*r.Email, r.PublicID)
		if err != nil {
			return domain.User{}, err
		}
		if emailOccupied {
			return domain.User{}, ErrUserUpdateEmailOccupied
		}
	}

	dbUser, err := uc.userRepository.Update(repositories.DBUserUpdateRequest{
		PublicID: r.PublicID,
		Name:     r.Name,
		Email:    r.Email,
		Role:     r.Role,
	})
	user := dbUser.User

	event := repositories.UserUpdatedEvent{
		PublicID: user.PublicID,
		Name:     user.Name,
		Email:    user.Email,
		Role:     user.Role,
	}

	if eventErr := uc.eventRepository.SendUserUpdated(event); eventErr != nil {
		uc.logger.
			Err(eventErr).
			Any("event", event).
			Msg("could not send UserUpdatedEvent")
	}
	return user, err
}
