package helper

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

//ConnectDB return the collection
func ConnectDB() *mongo.Collection {
	mongoURL := os.Getenv("MONGODB")
	if mongoURL == "" {
		mongoURL = "mongodb://localhost:27017"
	}
	clientOptions := options.Client().ApplyURI(mongoURL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Connected to MongoDB!")

	collection := client.Database("authentication-api").Collection("users")

	return collection
}

//ErrorResponse is a struct for sending errors
type ErrorResponse struct {
	Ok           bool   `json:"ok"`
	ErrorMessage string `json:"message"`
}

//GetError sends an ErrorResponse the error message and with a StatusInternalServerError code
func GetError(w http.ResponseWriter, err error) {
	log.Println(err.Error())
	var response = ErrorResponse{
		Ok:           false,
		ErrorMessage: err.Error(),
	}

	message, _ := json.Marshal(response)

	w.WriteHeader(http.StatusInternalServerError)
	w.Write(message)
}

//SendError sends an ErrorResponse with a custom message and status code
func SendError(w http.ResponseWriter, message string, statusCode int) {
	var response = ErrorResponse{
		Ok:           false,
		ErrorMessage: message,
	}

	payload, _ := json.Marshal(response)

	w.WriteHeader(statusCode)
	w.Write(payload)
}
