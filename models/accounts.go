package models

import (
	u "GopherGate/utils"
	"fmt"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

var db *gorm.DB // database

func init() {

	e := godotenv.Load() // Load .env file
	if e != nil {
		fmt.Print(e)
	}

	username := os.Getenv("db_user")
	password := os.Getenv("db_pass")
	dbName := os.Getenv("db_name")
	dbHost := os.Getenv("db_host")

	// Connection string is formed
	dbUri := fmt.Sprintf("host=%s user=%s dbname=%s sslmode=disable password=%s", dbHost, username, dbName, password)

	// If you have a PostgreSQL on Heroku, instead of these configurations,
	// you can directly use the database URL provided by Heroku
	// dbUri := fmt.Sprintf("postgres://xxxxx@xxx.compute.amazonaws.com:5432/ddjkb1easq2mec") // Database url

	fmt.Println(dbUri)

	conn, err := gorm.Open("postgres", dbUri)
	if err != nil {
		fmt.Print(err)
	}

	db = conn
	db.Debug().AutoMigrate(&Account{}) // Database migration
}

// returns a handle to the DB object
func GetDB() *gorm.DB {
	return db
}

// JWT struct
type Token struct {
	UserId   uint
	Username string
	jwt.StandardClaims
}

// User table struct
type Account struct {
	gorm.Model        // Specified to create accounts table during migration process on the database
	Email      string `json:"email"`
	Password   string `json:"password"`
	Token      string `json:"token";sql:"-"`
}

// Function to validate incoming information
func (account *Account) Validate() (map[string]interface{}, bool) {

	if !strings.Contains(account.Email, "@") {
		return u.Message(false, "Invalid email address!"), false
	}

	if len(account.Password) < 8 {
		return u.Message(false, "Your password must be at least 8 characters long!"), false
	}

	temp := &Account{}

	// Check if the email address is already registered
	err := GetDB().Table("accounts").Where("email = ?", account.Email).First(temp).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return u.Message(false, "Connection error occurred. Please try again!"), false
	}
	if temp.Email != "" {
		return u.Message(false, "Email address is already in use by another user."), false
	}

	return u.Message(false, "Everything is fine!"), true
}

// Function to create a user account
func (account *Account) Create() map[string]interface{} {

	if resp, ok := account.Validate(); !ok {
		return resp
	}

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(account.Password), bcrypt.DefaultCost)
	account.Password = string(hashedPassword)

	GetDB().Create(account)

	if account.ID <= 0 {
		return u.Message(false, "Connection error occurred. User could not be created!")
	}

	// JWT is created for the created account
	tk := &Token{UserId: account.ID}
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), tk)
	tokenString, _ := token.SignedString([]byte(os.Getenv("token_password")))
	account.Token = tokenString

	account.Password = "" // Password is removed from the response

	response := u.Message(true, "Account successfully created!")
	response["account"] = account
	return response
}

// Function for logging in
func Login(email, password string) map[string]interface{} {

	account := &Account{}
	err := GetDB().Table("accounts").Where("email = ?", email).First(account).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return u.Message(false, "Email address not found!")
		}
		return u.Message(false, "Connection error occurred. Please try again!")
	}

	err = bcrypt.CompareHashAndPassword([]byte(account.Password), []byte(password))
	if err != nil && err == bcrypt.ErrMismatchedHashAndPassword { // Password mismatch
		return u.Message(false, "Incorrect password! Please try again!")
	}

	// Login successful
	account.Password = ""

	// JWT is created
	tk := &Token{UserId: account.ID}
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), tk)
	tokenString, _ := token.SignedString([]byte(os.Getenv("token_password")))
	account.Token = tokenString // JWT is added to the response

	resp := u.Message(true, "Login successful!")
	resp["account"] = account
	return resp
}

// Function to get user information
func GetUser(u uint) *Account {
	acc := &Account{}
	GetDB().Table("accounts").Where("id = ?", u).First(acc)
	if acc.Email == "" { // User not found
		return nil
	}

	acc.Password = ""
	return acc
}
