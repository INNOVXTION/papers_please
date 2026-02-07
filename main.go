package main

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

type App struct {
	db map[string]Login
}

type Login struct {
	password      string
	session_token string
	csrf_token    string
}

func main() {
	server := http.NewServeMux()
	app := App{
		db: make(map[string]Login),
	}
	server.HandleFunc("POST /register", app.Register)
	server.HandleFunc("POST /login", app.Login)
	server.HandleFunc("POST /logout", app.Logout)
	server.HandleFunc("GET /protected", app.Protected)

	http.ListenAndServe(":8080", server)
}

func (app *App) Register(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	if _, ok := app.db[username]; ok {
		log.Println("username already exists")
		http.Error(w, "registration failed: username already exists", http.StatusBadRequest)
		return
	}

	hsh_pass, err := HashPassword(password)
	if err != nil {
		log.Println("hashing failed")
		http.Error(w, "registration failed", http.StatusInternalServerError)
		return
	}

	app.db[username] = Login{
		password: hsh_pass,
	}

	fmt.Fprintln(w, "registration successful")
}

func (app *App) Login(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	user, ok := app.db[username]
	if !ok || !CheckPassword(user.password, password) {
		log.Println("username doesnt exists")
		http.Error(w, "login failed: wrong username or password", http.StatusBadRequest)
		return
	}

	session_token := GenerateToken(32)
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    session_token,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
	})

	csrf_token := GenerateToken(32)
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    csrf_token,
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: false,
	})

	user.session_token = session_token
	user.csrf_token = csrf_token
	app.db[username] = user

	fmt.Fprintln(w, "login successful")
}

func (app *App) Logout(w http.ResponseWriter, r *http.Request) {
	if err := app.Authorize(r); err != nil {
		log.Println("Unauthorized access")
		http.Error(w, "unauthorzied", http.StatusUnauthorized)
		return
	}

	// clear cookies from response
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: true,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour),
		HttpOnly: false,
	})

	// clear cookies from DB
	username := r.FormValue("username")
	user, _ := app.db[username]
	user.csrf_token = ""
	user.session_token = ""
	app.db[username] = user

	fmt.Fprintln(w, "successfully logged out")
}

func (app *App) Protected(w http.ResponseWriter, r *http.Request) {
	if err := app.Authorize(r); err != nil {
		log.Println("Unauthorized access")
		http.Error(w, "unauthorzied", http.StatusUnauthorized)
		return
	}

	fmt.Fprintf(w, "welcome %v", r.FormValue("username"))
}
