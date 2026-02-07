package main

import (
	"errors"
	"net/http"
)

var AuthError = errors.New("unauthorized")

func (app *App) Authorize(r *http.Request) error {
	username := r.FormValue("username")
	login, ok := app.db[username]
	if !ok {
		return AuthError
	}

	session_cookie, err := r.Cookie("session_token")
	if err != nil {
		return AuthError
	}
	if session_cookie.Value != login.session_token || session_cookie.Value == "" {
		return AuthError
	}

	csrf_cookie := r.Header.Get("X-CSRF-Token")
	if csrf_cookie != login.csrf_token || csrf_cookie == "" {
		return AuthError
	}

	return nil
}
