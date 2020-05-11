package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/andreacoradi/auth/helper"
	"github.com/andreacoradi/auth/models"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/mongo"
)

var collection *mongo.Collection
var mySigningKey = []byte(os.Getenv("SECRET"))

func init() {
	if os.Getenv("SECRET") == "" {
		panic("You need to provide a secret!")
	}
	collection = helper.ConnectDB()
}

func addUser(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var user models.User
	_ = json.NewDecoder(r.Body).Decode(&user)

	count, _ := collection.CountDocuments(context.TODO(), models.User{Username: user.Username})

	if count != 0 {
		helper.SendError(w, "user already exists", 400)
		return
	}

	result, err := collection.InsertOne(context.TODO(), user)
	if err != nil {
		helper.GetError(w, err)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(result)
}

func getToken(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["username"]

	var user models.User
	_ = json.NewDecoder(r.Body).Decode(&user)

	if user.Password == "" {
		helper.SendError(w, "password not provided", 400)
		return
	}

	var dbUser models.User

	collection.FindOne(context.TODO(), models.User{Username: username}).Decode(&dbUser)

	if dbUser.Username == "" {
		helper.SendError(w, "user does not exist", http.StatusNotFound)
		return
	}

	if user.Password != dbUser.Password {
		helper.SendError(w, "wrong password", http.StatusForbidden)
		return
	}

	claims := &jwt.StandardClaims{
		ExpiresAt: 6 * time.Hour.Microseconds(),
		Issuer:    user.Username,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(mySigningKey)
	if err != nil {
		helper.GetError(w, err)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":      true,
		"data":    tokenString,
		"message": "login successful",
	})
}

func authenticate(w http.ResponseWriter, r *http.Request) {
	auth := r.Header["Authorization"]
	if len(auth) == 0 {
		helper.SendError(w, "no token provided", http.StatusForbidden)
		return
	}

	tokenString := strings.TrimSpace(
		strings.Split(auth[0], "Bearer")[1],
	)

	if tokenString == "" {
		helper.SendError(w, "token is empty", http.StatusForbidden)
		return
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("There was an error")
		}
		return mySigningKey, nil
	})

	if err != nil {
		helper.SendError(w, err.Error(), http.StatusForbidden)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":      token.Valid,
		"message": "authenticated",
	})
}

func main() {
	r := mux.NewRouter().StrictSlash(true)
	api := r.PathPrefix("/api/v1").Subrouter()

	//API Endpoints
	api.HandleFunc("/users", addUser).Methods("POST")
	api.HandleFunc("/users/{username}", getToken).Methods("POST")
	api.HandleFunc("/auth", authenticate).Methods("GET")

	port := os.Getenv("PORT")
	if port == "" {
		port = ":8080"
	}
	fmt.Printf("Running on port %s\n", port)
	log.Fatal(http.ListenAndServe(port, r))
}
