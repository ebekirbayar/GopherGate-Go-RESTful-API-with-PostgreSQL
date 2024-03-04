package app

import (
	"GopherGate/models"
	u "GopherGate/utils"
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
)

var JwtAuthentication = func(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		notAuth := []string{"/api/user/new", "/api/user/login"} // Endpoints that do not require authentication
		requestPath := r.URL.Path                               // current request path

		// Check if the incoming request needs authentication
		for _, value := range notAuth {
			if value == requestPath {
				next.ServeHTTP(w, r)
				return
			}
		}

		response := make(map[string]interface{})
		tokenHeader := r.Header.Get("Authorization") // Get token from header

		if tokenHeader == "" { // If no token is sent, return "403 Unauthorized" error
			response = u.Message(false, "Token must be sent!")
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			u.Respond(w, response)
			return
		}

		splitted := strings.Split(tokenHeader, " ") // Check if the token comes in the format "Bearer {token}" or "Token {token}"
		if len(splitted) != 2 {
			response = u.Message(false, "Invalid or malformed token!")
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			u.Respond(w, response)
			return
		}

		tokenPart := splitted[1] // Get the part of the token that allows us to verify it
		tk := &models.Token{}

		token, err := jwt.ParseWithClaims(tokenPart, tk, func(token *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("token_password")), nil
		})

		if err != nil { // If the token is invalid, return a "403" error
			response = u.Message(false, "Invalid token!")
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			u.Respond(w, response)
			return
		}

		if !token.Valid { // If the token is invalid, return a "403" error
			response = u.Message(false, "Invalid token!")
			w.WriteHeader(http.StatusForbidden)
			w.Header().Add("Content-Type", "application/json")
			u.Respond(w, response)
			return
		}

		// If verification is successful, proceed with the operation
		fmt.Sprintf("User %", tk.Username) // Print username to console
		ctx := context.WithValue(r.Context(), "user", tk.UserId)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}
