package usecases

import (
	"errors"

	"github.com/matveevtam/async-arch-homework/auth-service/internal/domain"
	"github.com/matveevtam/async-arch-homework/auth-service/internal/usecases/repositories"
	"github.com/rs/zerolog"
)

var (
	ErrUserLogInEmailNotFound     = errors.New("no user with such email")
	ErrUserLogInIncorrectPassword = errors.New("password is incorrect")
)

type UserLogInUseCase struct {
	repository repositories.UserRepository
	secretKey  []byte
	logger     zerolog.Logger
}

func NewUserLogInUseCase(repository repositories.UserRepository, secretKey []byte, logger zerolog.Logger) UserLogInUseCase {
	return UserLogInUseCase{
		repository: repository,
		secretKey:  secretKey,
		logger:     logger,
	}
}

type UserLogInRequest struct {
	Email    string
	Password string
}

func (uc UserLogInUseCase) LogIn(r UserLogInRequest) (domain.User, domain.UserToken, error) {
	dbUser, err := uc.repository.GetByEmail(r.Email)
	if errors.Is(err, repositories.ErrDBItemNotFound) {
		return domain.User{}, "", ErrUserLogInEmailNotFound
	}
	if err != nil {
		return domain.User{}, "", err
	}

	passwordHash := calcPasswordHash(r.Password, dbUser.PasswordSalt)
	if passwordHash != dbUser.PasswordHash {
		return domain.User{}, "", ErrUserLogInIncorrectPassword
	}

	user := dbUser.User

	token, err := makeUserToken(user, uc.secretKey)

	return user, token, err
}
