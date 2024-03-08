package main

// import "github.com/matveevtam/async-arch-homework/auth-service/internal"
import (
	"net/url"

	"github.com/matveevtam/async-arch-homework/auth-service/internal/domain"
	"github.com/matveevtam/async-arch-homework/auth-service/internal/infrastructure/dataproviders/memdataprovider"
	"github.com/matveevtam/async-arch-homework/auth-service/internal/infrastructure/endpoints"
	"github.com/matveevtam/async-arch-homework/auth-service/internal/infrastructure/eventbrokers/mockeventbroker"
	"github.com/matveevtam/async-arch-homework/auth-service/internal/usecases"
	"github.com/matveevtam/async-arch-homework/auth-service/internal/usecases/repositories"
	"github.com/rs/zerolog"
)

type AppConfig struct {
	Port             string
	Hostname         string
	UserSecretKey    []byte
	ServiceSecretKey []byte
}

var DefaultAppConfig = AppConfig{
	Port:             "1200",
	Hostname:         "localhost",
	UserSecretKey:    []byte("user-key-DSXVHs4Blj"),
	ServiceSecretKey: []byte("service-key-UEWHAkeemT"),
}

type Repositories struct {
	Events   repositories.EventRepository
	Services repositories.ServiceRepository
	Users    repositories.UserRepository
}

type UseCases struct {
	ServiceGet       usecases.ServiceGetUseCase
	ServiceAdd       usecases.ServiceAddUseCase
	ServiceCheckAuth usecases.ServiceCheckAuthUseCase
	ServiceLogIn     usecases.ServiceLogInUseCase
	UserAdd          usecases.UserAddUseCase
	UserCheckAuth    usecases.UserCheckAuthUseCase
	UserGet          usecases.UserGetUseCase
	UserLogIn        usecases.UserLogInUseCase
	UserUpdate       usecases.UserUpdateUseCase
}

type SubLoggerFn = func(string) zerolog.Logger

func main() {
	config := DefaultAppConfig

	hostPort := config.Hostname + ":" + config.Port
	baseURL := url.URL{
		Scheme: "http",
		Host:   hostPort,
	}

	zerolog.SetGlobalLevel(zerolog.DebugLevel)
	baseLogger := zerolog.New(zerolog.NewConsoleWriter())
	makeSubLogger := func(component string) zerolog.Logger { return baseLogger.With().Str("component", component).Logger() }

	repos := makeRepositories(config, makeSubLogger)

	useCases := makeUseCases(config, repos, makeSubLogger)
	useCases.UserAdd.AddUser(usecases.AddUserRequest{ActorRole: domain.RoleAdmin, Name: "Bob", Email: "bob@foo.com", Role: domain.RoleAdmin, Password: "123"})

	// Echo instance
	e := endpoints.NewAuthServiceEchoAPI(
		useCases.UserCheckAuth,
		useCases.UserGet,
		useCases.UserLogIn,
		useCases.UserAdd,
		useCases.UserUpdate,
		useCases.ServiceAdd,
		useCases.ServiceGet,
		useCases.ServiceLogIn,
		useCases.ServiceCheckAuth,
		baseURL,
		makeSubLogger("API"),
	)

	e.Logger.Fatal(e.Start(hostPort))
}

func makeRepositories(config AppConfig, subLoggerFn SubLoggerFn) Repositories {
	return Repositories{
		Events:   mockeventbroker.NewMockEventBroker(),
		Services: memdataprovider.NewInMemoryServiceRepository(),
		Users:    memdataprovider.NewInMemoryUserRepository(subLoggerFn("InMemoryUserRepository")),
	}
}

func makeUseCases(config AppConfig, repos Repositories, subLoggerFn SubLoggerFn) UseCases {
	return UseCases{
		ServiceGet:       usecases.NewServiceGetUseCase(repos.Services, subLoggerFn("ServiceGetUseCase")),
		ServiceAdd:       usecases.NewServiceAddUseCase(repos.Services),
		ServiceCheckAuth: usecases.NewServiceCheckAuthUseCase(config.ServiceSecretKey, config.UserSecretKey, subLoggerFn("ServiceCheckAuthUseCase")),
		ServiceLogIn:     usecases.NewServiceLogInUseCase(repos.Services, config.ServiceSecretKey),
		UserAdd:          usecases.NewUserAddUseCase(repos.Users, repos.Events, subLoggerFn("UserAddUseCase")),
		UserCheckAuth:    usecases.NewUserCheckAuthUseCase(config.UserSecretKey, subLoggerFn("UserCheckAuthUseCase")),
		UserGet:          usecases.NewUserGetUseCase(repos.Users, subLoggerFn("UserGetUseCase")),
		UserLogIn:        usecases.NewUserLogInUseCase(repos.Users, config.UserSecretKey, subLoggerFn("UserLogInUseCase")),
		UserUpdate:       usecases.NewUserUpdateUseCase(repos.Users, repos.Events, subLoggerFn("UserUpdateUseCase")),
	}
}
