package main

import (
	"GopherGate/app"
	"GopherGate/controllers"
	"fmt"
	"net/http"
	"os"

	"github.com/gorilla/mux"
)

func main() {
	router := mux.NewRouter()
	router.Use(app.JwtAuthentication) // JWT authentication middleware is added
	router.HandleFunc("/api/user/new", controllers.CreateAccount).Methods("POST")

	router.HandleFunc("/api/user/login", controllers.Authenticate).Methods("POST")
	port := os.Getenv("PORT") // Fetch port information from environment variables
	if port == "" {
		port = "8000" // Default to localhost:8000
	}

	fmt.Println(port)

	err := http.ListenAndServe(":"+port, router) // Start listening for requests on localhost:8000/api
	if err != nil {
		fmt.Print(err)
	}
}
