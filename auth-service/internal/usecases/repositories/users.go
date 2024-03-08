package repositories

import (
	"github.com/matveevtam/async-arch-homework/auth-service/internal/domain"
)

type DBUser struct {
	domain.User
	ID int
}

type DBUserUpdateRequest struct {
	PublicID domain.UserPublicID
	Name     *string
	Email    *string
	Role     *domain.UserRole
}

type UserRepository interface {
	List() ([]DBUser, error)
	GetByPublicID(domain.UserPublicID) (DBUser, error)
	GetByEmail(string) (DBUser, error)
	EmailExists(string) (bool, error)
	EmailBelongsToOther(string, domain.UserPublicID) (bool, error)
	Save(domain.User) (DBUser, error)
	Update(DBUserUpdateRequest) (DBUser, error)
}
