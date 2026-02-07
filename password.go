package main

import (
	"crypto/rand"
	"encoding/base64"
	"log"

	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	return string(bytes), err
}

func CheckPassword(hashed string, password string) bool {
	if err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password)); err == nil {
		return true
	} else {
		return false
	}
}

func GenerateToken(length int) string {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		log.Fatalf("randomizing failed")
	}
	return base64.URLEncoding.EncodeToString(bytes)
}
