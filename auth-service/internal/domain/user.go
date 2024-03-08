package domain

import (
	"encoding/json"

	"github.com/google/uuid"
)

type User struct {
	PublicID     UserPublicID
	Name         string
	Email        string
	Role         UserRole
	PasswordHash string
	PasswordSalt string
}

type UserPublicID uuid.UUID

func (id UserPublicID) String() string {
	return (uuid.UUID(id)).String()
}

func (id UserPublicID) MarshalJSON() ([]byte, error) {
	if id == [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} {
		return json.Marshal(nil)
	}
	return json.Marshal(id.String())
}

type UserToken string

type UserRole int

const (
	RoleWorker UserRole = iota
	RoleManager
	RoleAdmin
	RoleBoss
)

var AllUserRoles = []UserRole{RoleWorker, RoleManager, RoleAdmin, RoleBoss}

var roleNames = [...]string{"worker", "manager", "admin", "boss"}

func (r UserRole) String() string {
	return roleNames[int(r)]
}

func (r UserRole) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.String())
}

func RoleFromString(s string) (UserRole, bool) {
	for i, v := range roleNames {
		if s == v {
			return UserRole(i), true
		}
	}
	return UserRole(0), false
}
