package repositories

import "github.com/matveevtam/async-arch-homework/auth-service/internal/domain"

type UserAddedEvent struct {
	PublicID domain.UserPublicID
	Name     string
	Email    string
	Role     domain.UserRole
}

type UserUpdatedEvent struct {
	PublicID domain.UserPublicID
	Name     string
	Email    string
	Role     domain.UserRole
}

type EventRepository interface {
	SendUserAdded(UserAddedEvent) error
	SendUserUpdated(UserUpdatedEvent) error
}
