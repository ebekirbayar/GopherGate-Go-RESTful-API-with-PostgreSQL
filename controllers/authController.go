package controllers

import (
	"GopherGate/models"
	u "GopherGate/utils"
	"encoding/json"
	"net/http"
)

var CreateAccount = func(w http.ResponseWriter, r *http.Request) {

	account := &models.Account{}
	err := json.NewDecoder(r.Body).Decode(account) // Request body is decoded, and if there's an error, it's returned
	if err != nil {
		u.Respond(w, u.Message(false, "Invalid request. Please check again!"))
		return
	}

	resp := account.Create() // Create account
	u.Respond(w, resp)
}

var Authenticate = func(w http.ResponseWriter, r *http.Request) {

	account := &models.Account{}
	err := json.NewDecoder(r.Body).Decode(account) // Request body is decoded, and if there's an error, it's returned
	if err != nil {
		u.Respond(w, u.Message(false, "Invalid request. Please check again!"))
		return
	}

	resp := models.Login(account.Email, account.Password) // Authenticate
	u.Respond(w, resp)
}
