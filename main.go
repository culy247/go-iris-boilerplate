package main

import (
	"fmt"
	"go-iris-boilerplate/config"
	"go-iris-boilerplate/controllers"
	"go-iris-boilerplate/database"
	"go-iris-boilerplate/models"
	"os"
	"time"

	"github.com/kataras/iris"
	"github.com/kataras/iris/core/router"

	"github.com/kataras/iris/middleware/jwt"
	"github.com/kataras/iris/middleware/logger"
	"github.com/kataras/iris/middleware/recover"
)

const (
	accessTokenMaxAge  = 10 * time.Minute
	refreshTokenMaxAge = time.Hour
	secretKey = "secret"
)

var (
	signer   := NewSigner(HS256, secretKey, accessTokenMaxAge)
	verifier := NewVerifier(HS256, secretKey)
)

// UserClaims a custom access claims structure.
type UserClaims struct {
	ID string `json:"user_id"`
}

func newApp() (app *iris.Application) {
	app = iris.New()
	app.Use(recover.New())
	app.Use(logger.New())

	app.OnErrorCode(iris.StatusInternalServerError, func(ctx iris.Context) {
		ctx.WriteString("Oups something went wrong, try again")
	})

	database.DB.AutoMigrate(
		&models.User{}
	)

	iris.RegisterOnInterrupt(func() {
		database.DB.Close()
	})

	app.OnErrorCode(iris.StatusUnauthorized, handleUnauthorized)

	auth := app.Party("/auth").AllowMethods(iris.MethodOptions)
	{
		auth.Post("/signup", controllers.UserSignup)
		auth.Post("/verify-email", controllers.VerifyEmail)
		auth.Post("/login", controllers.UserLogin)
		auth.Post("/forgot-password", controllers.ForgotPassword)
		auth.Post("/reset-password", controllers.ResetPassword)
		// auth.Get("/email", controllers.Email)
		app.Get("/authenticate", generateTokenPair)
		app.Get("/refresh", refreshToken)
	}

	v1 := app.Party("/v1").AllowMethods(iris.MethodOptions)
	{
		verifyMiddleware := verifier.Verify(func() interface{} {
			return new(UserClaims)
		})

		v1.Use(verifyMiddleware)

		v1.PartyFunc("/users", func(users router.Party) {
			users.Get("/{id:uint}", controllers.GetUser)
			users.Get("/", controllers.GetAllUsers)
			// users.Post("/", controllers.CreateUser)
			users.Put("/{id:uint}", controllers.UpdateUser)
		})
	}

	return
}

func main() {
	app := newApp()
	fmt.Printf("Environment: %s", os.Getenv("ENV_MODE"))

	addr := config.Conf.Get("app.addr").(string)
	app.Run(iris.Addr(addr))
}
