package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/andreacoradi/auth/helper"
	"github.com/andreacoradi/auth/models"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
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

	user.Username = strings.TrimSpace(user.Username)
	user.Password = strings.TrimSpace(user.Password)

	count, _ := collection.CountDocuments(context.TODO(), models.User{Username: user.Username})

	if count != 0 {
		helper.SendError(w, fmt.Sprintf("user `%s` already exists", user.Username), http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)

	if err != nil {
		helper.GetError(w, err)
		return
	}

	user.Password = string(hashedPassword)

	if _, err := collection.InsertOne(context.TODO(), user); err != nil {
		helper.GetError(w, err)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":      true,
		"message": "user successfully created",
	})
}

func getToken(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["username"]

	var passwordField models.User
	_ = json.NewDecoder(r.Body).Decode(&passwordField)

	if passwordField.Password == "" {
		helper.SendError(w, "password not provided", http.StatusBadRequest)
		return
	}

	var dbUser models.User

	collection.FindOne(context.TODO(), models.User{Username: username}).Decode(&dbUser)

	if dbUser.Username == "" {
		helper.SendError(w, fmt.Sprintf("user `%s` does not exist", username), http.StatusNotFound)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(dbUser.Password), []byte(passwordField.Password)); err != nil {
		helper.SendError(w, "wrong password", http.StatusForbidden)
		return
	}

	claims := &jwt.StandardClaims{
		ExpiresAt: time.Now().Local().Add(24 * time.Hour).Unix(),
		Issuer:    dbUser.Username,
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

	username := token.Claims.(jwt.MapClaims)["iss"]

	if username == nil || username == "" {
		helper.GetError(w, errors.New("no issuer found"))
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":       token.Valid,
		"message":  "authenticated",
		"username": username,
	})
}

func changePassword(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["username"]

	password := struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}{}

	err := json.NewDecoder(r.Body).Decode(&password)
	if err != nil {
		helper.SendError(w, err.Error(), http.StatusBadRequest)
		return
	}

	if password.NewPassword == password.OldPassword {
		helper.SendError(w, "new password must be different", http.StatusForbidden)
		return
	}

	var dbUser models.User

	result := collection.FindOne(context.TODO(), models.User{Username: username})
	if result.Err() != nil {
		helper.SendError(w, fmt.Sprintf("no user '%s' found", username), http.StatusNotFound)
		return
	}

	result.Decode(&dbUser)

	if err := bcrypt.CompareHashAndPassword([]byte(dbUser.Password), []byte(password.OldPassword)); err != nil {
		helper.SendError(w, "wrong password", http.StatusForbidden)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password.NewPassword), bcrypt.DefaultCost)

	if err != nil {
		helper.GetError(w, err)
		return
	}

	update := bson.D{
		primitive.E{
			Key: "$set",
			Value: models.User{
				Password: string(hashedPassword),
			},
		}}

	result = collection.FindOneAndUpdate(context.TODO(), models.User{Username: username}, update)

	if result.Err() != nil {
		helper.SendError(w, result.Err().Error(), http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":      true,
		"message": "password was successfully changed",
	})
}

func handlerUser(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		getToken(w, r)
	case "PUT":
		changePassword(w, r)
	default:
		panic("method not allowed")
	}
}

func main() {
	r := mux.NewRouter().StrictSlash(true)
	api := r.PathPrefix("/api/v1").Subrouter()

	//API Endpoints
	api.HandleFunc("/users", addUser).Methods("POST")
	api.HandleFunc("/users/{username}", handlerUser).Methods("POST", "PUT")
	api.HandleFunc("/auth", authenticate).Methods("GET")

	port := os.Getenv("PORT")
	if port == "" {
		port = ":8080"
	} else {
		port = ":" + port
	}

	headers := handlers.AllowedHeaders([]string{"X-Requested-With", "Content-Type", "Authorization"})
	methods := handlers.AllowedMethods([]string{"GET", "POST", "PUT", "HEAD", "OPTIONS"})
	origins := handlers.AllowedOrigins([]string{"*"})

	fmt.Printf("Running on port %s\n", port)
	log.Fatal(http.ListenAndServe(port, handlers.CORS(headers, methods, origins)(r)))
}
