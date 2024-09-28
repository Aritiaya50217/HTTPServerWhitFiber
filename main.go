package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/template/html/v2"
	"github.com/golang-jwt/jwt"
	"github.com/joho/godotenv"
)

func uploadImage(c *fiber.Ctx) error {
	// Read file from request
	file, err := c.FormFile("image")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).SendString(err.Error())
	}
	// save the file to the server
	err = c.SaveFile(file, "./uploads/"+file.Filename)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString(err.Error())
	}
	return c.SendString("File uploaded successfully : " + file.Filename)
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

func renderTemplate(c *fiber.Ctx) error {
	return c.Render("template", fiber.Map{
		"Name": "World",
	})
}

// config
func getConfig(c *fiber.Ctx) error {
	secretKey := getEnv("SECRET_KEY", "defaultSecret")
	return c.JSON(fiber.Map{
		"secret_key": secretKey,
	})
}

// middleware
func logginMiddleware(c *fiber.Ctx) error {
	// start timer
	start := time.Now()
	// process request
	err := c.Next()

	// calculate processing time
	duration := time.Since(start)

	// log the information
	fmt.Printf("Request URL: %s - Method: %s - Duration: %s\n", c.OriginalURL(), c.Method(), duration)

	return err
}

func main() {
	// initialize stanard Go html template engine
	engine := html.New("./views", ".html")

	// load env from .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// pass thw engine to fiber
	app := fiber.New(fiber.Config{
		Views: engine,
	})

	// Use the logging middleware
	app.Use(logginMiddleware)

	// jwt secret key
	secretKey := "secret"
	// login route
	app.Post("/login", login(secretKey))

	// JWT Middleware
	app.Use(jwtware.New(jwtware.Config{
		SigningKey: []byte(secretKey),
	}))

	// Middleware to extract user data from JWT
	app.Use(extractUserFromJWT)

	// apply cors middleware
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*", // adjust this to be more restrictive if needed
		AllowMethods: "GET,POST,HEAD,PUT,DELETE,PATCH",
		AllowHeaders: "Origin,Content-Type,Accept",
	}))

	// Setup routes
	app.Get("/book", getBooks)
	app.Get("/book/:id", getBook)
	app.Post("/book", createBook)
	app.Put("/book/:id", updateBook)
	app.Delete("/book/:id", deleteBook)
	app.Post("/upload", uploadImage)
	app.Get("/template", renderTemplate)
	app.Get("/api/config", getConfig)

	app.Listen(":8080")
}

var user = struct {
	Email    string
	Password string
}{
	Email:    "user@example.com",
	Password: "password123",
}

func login(secretKey string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		type LoginRequest struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		var request LoginRequest
		if err := c.BodyParser(&request); err != nil {
			return err
		}
		// check credentials - in real world , you should check against a database
		if request.Email != user.Email || request.Password != user.Password {
			return fiber.ErrUnauthorized
		}
		// create token
		token := jwt.New(jwt.SigningMethodES256)

		// set claims
		claims := token.Claims.(jwt.MapClaims)
		claims["email"] = user.Email
		claims["role"] = "admin"
		claims["exp"] = time.Now().Add(time.Hour * 72).Unix()

		// generate encoded token
		t, err := token.SignedString([]byte(secretKey))
		if err != nil {
			return c.SendStatus(fiber.StatusInternalServerError)
		}
		return c.JSON(fiber.Map{"token": t})
	}
}

// UserData represents the user data extracted from the JWT token
type UserData struct {
	Email string
	Role  string
}

// userContextKey is the key used to store user data in the Fiber context
const userContextKey = "user"

// extractUserFromJWT is a middleware the extracts user data from the JWT token
func extractUserFromJWT(c *fiber.Ctx) error {
	user := &UserData{}

	// extract the token from the Fiber context
	token := c.Locals("user").(*jwt.Token)
	claims := token.Claims.(jwt.MapClaims)

	fmt.Println(claims)
	user.Email = claims["email"].(string)
	user.Role = claims["role"].(string)

	// store the user data in the Fiber context
	c.Locals(userContextKey, user)
	return c.Next()
}

func isAdmin(c *fiber.Ctx) error {
	user := c.Locals(userContextKey).(*UserData)
	if user.Role != "admin" {
		return fiber.ErrUnauthorized
	}
	return c.Next()
}
