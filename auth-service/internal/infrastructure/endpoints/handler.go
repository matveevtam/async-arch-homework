package endpoints

import (
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/matveevtam/async-arch-homework/auth-service/internal/domain"
	"github.com/matveevtam/async-arch-homework/auth-service/internal/usecases"
	"github.com/rs/zerolog"
)

type APIHandler struct {
	userLogInUseCase        usecases.UserLogInUseCase
	userCheckAuthUseCase    usecases.UserCheckAuthUseCase
	userGetUseCase          usecases.UserGetUseCase
	userAddUseCase          usecases.UserAddUseCase
	userUpdateUseCase       usecases.UserUpdateUseCase
	serviceAddUseCase       usecases.ServiceAddUseCase
	serviceGetUseCase       usecases.ServiceGetUseCase
	serviceLogInUseCase     usecases.ServiceLogInUseCase
	serviceCheckAuthUseCase usecases.ServiceCheckAuthUseCase
	logInURL                url.URL
	meURL                   url.URL
	logger                  zerolog.Logger
}

func NewAuthServiceEchoAPI(
	userCheckAuthUseCase usecases.UserCheckAuthUseCase,
	userGetUseCase usecases.UserGetUseCase,
	userLogInUseCase usecases.UserLogInUseCase,
	userAddUseCase usecases.UserAddUseCase,
	userUpdateUseCase usecases.UserUpdateUseCase,
	serviceAddUseCase usecases.ServiceAddUseCase,
	serviceGetUseCase usecases.ServiceGetUseCase,
	serviceLogInUseCase usecases.ServiceLogInUseCase,
	serviceCheckAuthUseCase usecases.ServiceCheckAuthUseCase,
	baseURL url.URL,
	logger zerolog.Logger,
) *echo.Echo {
	e := echo.New()

	recoverConfig := middleware.DefaultRecoverConfig
	recoverConfig.LogErrorFunc = func(c echo.Context, err error, stack []byte) error {
		logger.Err(err).Msg("Recovered from panic")
		println(string(stack))
		return nil
	}
	e.Use(middleware.RecoverWithConfig(recoverConfig))

	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			start := time.Now()
			err := next(c)
			if err != nil {
				c.Error(err)
			}
			end := time.Now()

			req := c.Request()
			resp := c.Response()
			reqSize := req.Header.Get(echo.HeaderContentLength)
			if reqSize == "" {
				reqSize = "0"
			}
			respSize := strconv.FormatInt(resp.Size, 10)
			logger.Info().
				Str("method", req.Method).
				Str("url", req.URL.String()).
				Int("status", resp.Status).
				Err(err).
				Str("latency_human", end.Sub(start).String()).
				Str("bytes_in", reqSize).
				Str("bytes_out", respSize).
				Msg("request logged")
			return nil
		}
	})

	htmlErrorHandler := func(err error, c echo.Context) {
		code := http.StatusInternalServerError
		if httpErr, ok := err.(*echo.HTTPError); ok {
			code = httpErr.Code
			if apiErr, ok := httpErr.Message.(APIError); ok {
				if err = c.JSON(code, apiErr); err != nil {
					logger.Error().Err(err).Msg("Could not send APIError as JSON")
				}
				return
			}
		}
		renderData := struct {
			Code    int
			Message string
		}{Code: code, Message: err.Error()}
		if err := c.Render(code, "error", renderData); err != nil {
			logger.Error().Err(err).Msg("Could not render error page")
		}
	}

	e.HTTPErrorHandler = htmlErrorHandler

	t := &Template{
		templates: template.Must(template.ParseGlob("internal/infrastructure/endpoints/views/*.html")),
	}
	e.Renderer = t

	logInURL := baseURL
	logInURL.Path = "/login"
	meURL := baseURL
	meURL.Path = "/me"
	handler := APIHandler{
		userCheckAuthUseCase:    userCheckAuthUseCase,
		userGetUseCase:          userGetUseCase,
		userLogInUseCase:        userLogInUseCase,
		userAddUseCase:          userAddUseCase,
		userUpdateUseCase:       userUpdateUseCase,
		serviceAddUseCase:       serviceAddUseCase,
		serviceGetUseCase:       serviceGetUseCase,
		serviceLogInUseCase:     serviceLogInUseCase,
		serviceCheckAuthUseCase: serviceCheckAuthUseCase,
		logInURL:                logInURL,
		meURL:                   meURL,
		logger:                  logger,
	}

	e.GET("/login", handler.LogInGet)
	e.POST("/login", handler.LogInPost)
	e.GET("/me", handler.MeGet)

	e.GET("/users/add", handler.UserAddGet)
	e.GET("/users", handler.UsersGet)
	e.POST("/users", handler.UsersPost)
	e.GET("/users/:id", handler.UserGet)
	e.GET("/users/:id/update", handler.UserUpdateGet)
	e.PUT("/users/:id", handler.UserPut)

	e.GET("/services", handler.ServicesGet)
	e.GET("/services/add", handler.ServiceAddGet)
	e.POST("/services", handler.ServicesPost)

	g := e.Group("/internal")
	g.POST("/newToken", handler.InternalServiceNewToken)
	g.POST("/checkAuth", handler.InternalServiceCheckAuth)

	return e
}

type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e APIError) Error() string {
	return e.Code + ": " + e.Message
}

type Template struct {
	templates *template.Template
}

func (t *Template) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

func (h APIHandler) checkCookie(c echo.Context) (usecases.UserCheckAuthResponse, bool) {
	cookie, err := c.Cookie("papug")
	if err == http.ErrNoCookie {
		h.logger.Debug().Msg("No cookie!")
		return usecases.UserCheckAuthResponse{}, false
	}
	if err != nil {
		h.logger.Err(err).Str("requestURI", c.Request().RequestURI).Msg("unexpected error while checking user cookie")
		return usecases.UserCheckAuthResponse{}, false
	}
	userToken := domain.UserToken(cookie.Value)
	userInfo := h.userCheckAuthUseCase.CheckUserAuth(usecases.UserCheckAuthRequest{Token: userToken})
	h.logger.Debug().Msg("checkCookie OK!")
	return userInfo, true
}

func (h APIHandler) redirectToLogIn(c echo.Context) error {
	u := h.logInURL
	u.RawQuery = url.Values{"redirect": []string{c.Request().URL.String()}}.Encode()
	return c.Redirect(http.StatusSeeOther, u.String())
}

func (h APIHandler) redirectAfterLogIn(c echo.Context) error {
	u := c.Request().URL.Query().Get("redirect")
	if u == "" {
		u = h.meURL.String()
	}
	return c.Redirect(http.StatusSeeOther, u)
}

type userInfoRenderData struct {
	PublicID domain.UserPublicID
	Name     string
	Email    string
	Role     domain.UserRole
}

type userUpdateRenderData struct {
	ErrEmailOccupied bool
	RoleOptions      []domain.UserRole
	Name             string
	Email            string
	Role             domain.UserRole
}

type userListRenderData struct {
	UserInfos []userInfoRenderData
}

type userAddRenderData struct {
	ErrEmailOccupied    bool
	ErrPasswordTooShort bool
	RoleOptions         []domain.UserRole
	Name                string
	Email               string
	Role                domain.UserRole
	Password            string
}

type userLogInRenderData struct {
	ErrEmail    bool
	ErrPassword bool
}

type serviceInfoRenderData struct {
	Name   string
	Secret string
}

type serviceListRenderData struct {
	ServiceInfos []serviceInfoRenderData
}

type serviceAddRenderData struct {
	ErrNameOccupied bool
	Name            string
}

func (h APIHandler) LogInGet(c echo.Context) error {
	return c.Render(http.StatusOK, "userLogIn", userLogInRenderData{})
}

func (h APIHandler) LogInPost(c echo.Context) error {
	err := c.Request().ParseForm()
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}
	_, token, err := h.userLogInUseCase.LogIn(usecases.UserLogInRequest{
		Email:    c.Request().FormValue("email"),
		Password: c.Request().FormValue("password"),
	})
	h.logger.Info().Err(err).Msg("error from log in use case")
	if err == usecases.ErrUserLogInEmailNotFound || err == usecases.ErrUserLogInIncorrectPassword {
		return c.Render(http.StatusOK, "userLogIn", userLogInRenderData{
			ErrEmail:    err == usecases.ErrUserLogInEmailNotFound,
			ErrPassword: err == usecases.ErrUserLogInIncorrectPassword,
		})
	}
	if err != nil {
		return err
	}

	c.SetCookie(&http.Cookie{Name: "papug", Value: string(token), HttpOnly: true})

	return h.redirectAfterLogIn(c)
}

func (h APIHandler) MeGet(c echo.Context) error {
	userInfo, ok := h.checkCookie(c)
	if !ok || !userInfo.UserAuthOK {
		return h.redirectToLogIn(c)
	}

	user, err := h.userGetUseCase.GetUserByPublicID(usecases.GetUserByPublicIDRequest{
		ActorRole:     userInfo.UserRole,
		ActorPublicID: userInfo.UserPublicID,
		UserPublicID:  userInfo.UserPublicID,
	})
	if err == usecases.ErrUserGetNotFound || err == usecases.ErrUserGetNotAllowed {
		return h.redirectToLogIn(c)
	}
	if err != nil {
		return err
	}

	return c.Render(http.StatusOK, "userInfo", userInfoRenderData{
		PublicID: user.PublicID,
		Name:     user.Name,
		Email:    user.Email,
		Role:     user.Role,
	})
}

func (h APIHandler) UsersGet(c echo.Context) error {
	userInfo, ok := h.checkCookie(c)
	if !ok || !userInfo.UserAuthOK {
		return h.redirectToLogIn(c)
	}

	users, err := h.userGetUseCase.ListUsers(usecases.ListUsersRequest{
		ActorRole: userInfo.UserRole,
	})
	if err == usecases.ErrUserGetNotAllowed {
		return echo.NewHTTPError(http.StatusMethodNotAllowed, "you are not allowed to do that")
	}
	if err != nil {
		return err
	}

	userInfos := make([]userInfoRenderData, len(users))
	for i, u := range users {
		userInfos[i] = userInfoRenderData{
			PublicID: u.PublicID,
			Name:     u.Name,
			Email:    u.Email,
			Role:     u.Role,
		}
	}

	return c.Render(http.StatusOK, "userList", userListRenderData{UserInfos: userInfos})
}

func (h APIHandler) UserAddGet(c echo.Context) error {
	return c.Render(http.StatusOK, "userAdd", userAddRenderData{
		RoleOptions: domain.AllUserRoles,
	})
}

func (h APIHandler) UsersPost(c echo.Context) error {
	userInfo, ok := h.checkCookie(c)
	if !ok || !userInfo.UserAuthOK {
		return h.redirectToLogIn(c)
	}

	err := c.Request().ParseForm()
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "could not parse form: "+err.Error())
	}
	req := c.Request()

	var (
		name     = req.FormValue("name")
		email    = req.FormValue("email")
		roleStr  = req.FormValue("role")
		password = req.FormValue("password")
	)
	role, roleOK := domain.RoleFromString(roleStr)
	if !roleOK {
		return echo.NewHTTPError(http.StatusBadRequest, "role has invalid value: `"+roleStr+"`")
	}
	renderData := userAddRenderData{
		RoleOptions: domain.AllUserRoles,
		Name:        name,
		Email:       email,
		Role:        role,
		Password:    password,
	}

	_, err = h.userAddUseCase.AddUser(usecases.AddUserRequest{
		ActorRole: userInfo.UserRole,
		Name:      name,
		Email:     email,
		Role:      role,
		Password:  password,
	})
	if err == usecases.ErrUserAddNotAllowed {
		return echo.NewHTTPError(http.StatusMethodNotAllowed, "you are not allowed to do that")
	}
	if err == usecases.ErrUserAddEmailOccupied {
		renderData.ErrEmailOccupied = true
		return c.Render(http.StatusBadRequest, "userAdd", renderData)
	}
	if err == usecases.ErrUserAddPasswordTooShort {
		renderData.ErrPasswordTooShort = true
		return c.Render(http.StatusBadRequest, "userAdd", renderData)
	}
	if err != nil {
		return err
	}

	return c.Redirect(http.StatusSeeOther, "/users")
}

func (h APIHandler) UserGet(c echo.Context) error {
	iDParam := c.Param("id")
	userPublicID, err := uuid.Parse(iDParam)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "malformed user id: `"+iDParam+"`")
	}

	userInfo, ok := h.checkCookie(c)
	if !ok || !userInfo.UserAuthOK {
		return h.redirectToLogIn(c)
	}

	user, err := h.userGetUseCase.GetUserByPublicID(usecases.GetUserByPublicIDRequest{
		ActorRole:     userInfo.UserRole,
		ActorPublicID: userInfo.UserPublicID,
		UserPublicID:  domain.UserPublicID(userPublicID),
	})
	if err == usecases.ErrUserGetNotAllowed {
		return echo.NewHTTPError(http.StatusMethodNotAllowed, "you are not allowed to do that")
	}
	if err == usecases.ErrUserGetNotFound {
		return echo.NewHTTPError(http.StatusNotFound, "user not found")
	}
	if err != nil {
		return err
	}

	return c.Render(http.StatusOK, "userInfo", userInfoRenderData{
		PublicID: user.PublicID,
		Name:     user.Name,
		Email:    user.Email,
		Role:     user.Role,
	})
}

func (h APIHandler) UserUpdateGet(c echo.Context) error {
	iDParam := c.Param("id")
	userPublicID, err := uuid.Parse(iDParam)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "malformed user id: `"+iDParam+"`")
	}

	userInfo, ok := h.checkCookie(c)
	if !ok || !userInfo.UserAuthOK {
		return h.redirectToLogIn(c)
	}

	user, err := h.userGetUseCase.GetUserByPublicID(usecases.GetUserByPublicIDRequest{
		ActorRole:     userInfo.UserRole,
		ActorPublicID: userInfo.UserPublicID,
		UserPublicID:  domain.UserPublicID(userPublicID),
	})
	if err == usecases.ErrUserGetNotAllowed {
		return echo.NewHTTPError(http.StatusMethodNotAllowed, "you are not allowed to do that")
	}
	if err == usecases.ErrUserGetNotFound {
		return echo.NewHTTPError(http.StatusNotFound, "user not found")
	}
	if err != nil {
		return err
	}

	renderData := userUpdateRenderData{
		Name:        user.Name,
		Email:       user.Email,
		Role:        user.Role,
		RoleOptions: domain.AllUserRoles,
	}

	return c.Render(http.StatusOK, "userUpdate", renderData)
}

func (h APIHandler) UserPut(c echo.Context) error {
	iDParam := c.Param("id")
	userPublicID, err := uuid.Parse(iDParam)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "malformed user id: `"+iDParam+"`")
	}

	userInfo, ok := h.checkCookie(c)
	if !ok || !userInfo.UserAuthOK {
		return h.redirectToLogIn(c)
	}

	err = c.Request().ParseForm()
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "could not parse form: "+err.Error())
	}
	req := c.Request()

	var (
		name    = req.FormValue("name")
		email   = req.FormValue("email")
		roleStr = req.FormValue("role")
	)
	role, roleOK := domain.RoleFromString(roleStr)
	if !roleOK {
		return echo.NewHTTPError(http.StatusBadRequest, "role has invalid value: `"+roleStr+"`")
	}

	user, err := h.userUpdateUseCase.UpdateUser(usecases.UserUpdateRequest{
		ActorRole: userInfo.UserRole,
		PublicID:  domain.UserPublicID(userPublicID),
		Name:      &name,
		Email:     &email,
		Role:      &role,
	})
	if err == usecases.ErrUserUpdateNotAllowed {
		return echo.NewHTTPError(http.StatusMethodNotAllowed, "you are not allowed to do that")
	}
	if err == usecases.ErrUserUpdateEmailOccupied {
		return c.Render(http.StatusBadRequest, "userUpdate", userUpdateRenderData{
			ErrEmailOccupied: true,
			RoleOptions:      domain.AllUserRoles,
			Name:             name,
			Email:            email,
			Role:             role,
		})
	}
	if err != nil {
		return err
	}

	return c.Render(http.StatusOK, "userInfo", userInfoRenderData{
		PublicID: user.PublicID,
		Name:     user.Name,
		Email:    user.Email,
		Role:     user.Role,
	})
}

func (h APIHandler) ServicesGet(c echo.Context) error {
	userInfo, ok := h.checkCookie(c)
	if !ok || !userInfo.UserAuthOK {
		return h.redirectToLogIn(c)
	}

	services, err := h.serviceGetUseCase.ListServices(usecases.ListServicesRequest{
		ActorRole: userInfo.UserRole,
	})
	if err == usecases.ErrServiceGetNotAllowed {
		return echo.NewHTTPError(http.StatusMethodNotAllowed, "you are not allowed to do that")
	}
	if err != nil {
		return err
	}

	serviceInfos := make([]serviceInfoRenderData, len(services))
	for i, s := range services {
		serviceInfos[i] = serviceInfoRenderData{
			Name:   s.Name,
			Secret: s.Secret,
		}
	}

	return c.Render(http.StatusOK, "serviceList", serviceListRenderData{ServiceInfos: serviceInfos})
}

func (h APIHandler) ServiceAddGet(c echo.Context) error {
	return c.Render(http.StatusOK, "serviceAdd", serviceAddRenderData{})
}

func (h APIHandler) ServicesPost(c echo.Context) error {
	userInfo, ok := h.checkCookie(c)
	if !ok || !userInfo.UserAuthOK {
		return h.redirectToLogIn(c)
	}

	err := c.Request().ParseForm()
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "could not parse form: "+err.Error())
	}
	req := c.Request()

	var (
		name = req.FormValue("name")
	)

	_, err = h.serviceAddUseCase.AddService(usecases.AddServiceRequest{
		ActorRole: userInfo.UserRole,
		Name:      name,
	})
	if err == usecases.ErrServiceAddNotAllowed {
		return echo.NewHTTPError(http.StatusMethodNotAllowed, "you are not allowed to do that")
	}
	if err == usecases.ErrServiceAddAlreadyExists {
		return c.Render(http.StatusBadRequest, "serviceAdd", serviceAddRenderData{
			ErrNameOccupied: true,
			Name:            name,
		})
	}
	if err != nil {
		return err
	}

	return c.Redirect(http.StatusSeeOther, "/services")
}

type ServiceNewTokenRequestData struct {
	Name   string `json:"name" validate:"required"`
	Secret string `json:"secret" validate:"required"`
}

type ServiceNewTokenResponseData struct {
	Token string `json:"token"`
}

func (h APIHandler) InternalServiceNewToken(c echo.Context) (err error) {
	reqData := new(ServiceNewTokenRequestData)
	if err = c.Bind(&reqData); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, APIError{Code: "BADREQUEST", Message: err.Error()})
	}

	token, err := h.serviceLogInUseCase.LogIn(usecases.ServiceLogInRequest{
		Name:   reqData.Name,
		Secret: reqData.Secret,
	})
	if err == usecases.ErrServiceLogInNameNotFound {
		return echo.NewHTTPError(http.StatusBadRequest, APIError{Code: "NOTFOUND", Message: err.Error()})
	}
	if err == usecases.ErrServiceLogInIncorrectSecret {
		return echo.NewHTTPError(http.StatusUnauthorized, APIError{Code: "SECRETINCORRECT", Message: err.Error()})
	}
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, APIError{Code: "UNKNOWN", Message: err.Error()})
	}

	return c.JSON(http.StatusOK, ServiceNewTokenResponseData{Token: string(token)})
}

type ServiceCheckAuthRequestData struct {
	ServiceToken string `json:"serviceToken"`
	UserToken    string `json:"userToken"`
}

type ServiceCheckAuthResponseData struct {
	IsServiceAuthOK bool                 `json:"isServiceAuthOK"`
	ServiceName     *string              `json:"serviceName"`
	IsUserAuthOK    bool                 `json:"isUserAuthOK"`
	UserPublicID    *domain.UserPublicID `json:"userPublicID"`
	UserRole        *domain.UserRole     `json:"userRole"`
}

func (h APIHandler) InternalServiceCheckAuth(c echo.Context) (err error) {
	reqData := new(ServiceCheckAuthRequestData)
	if err = c.Bind(&reqData); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, APIError{Code: "BADREQUEST", Message: err.Error()})
	}

	resp := h.serviceCheckAuthUseCase.CheckServiceAuth(usecases.ServiceCheckAuthRequest{
		SericeToken: domain.ServiceToken(reqData.ServiceToken),
		UserToken:   domain.UserToken(reqData.UserToken),
	})

	respData := ServiceCheckAuthResponseData{
		IsServiceAuthOK: resp.IsServiceAuthOK,
		IsUserAuthOK:    resp.IsUserAuthOK,
	}
	if resp.IsServiceAuthOK {
		respData.ServiceName = &resp.ServiceName
	}
	if resp.IsUserAuthOK {
		respData.UserPublicID = &resp.UserPublicID
		respData.UserRole = &resp.UserRole
	}

	return c.JSON(http.StatusOK, respData)
}
