package main

import (
	"context"
	"fmt"
	"helseid-golang-m2m-app/auth"
	"io/ioutil"
	"log"
	"net/http"
)

func main() {
	client := auth.NewClient(context.Background())

	resp, err := client.Get("http://localhost:3123/foo")
	if err != nil {
		log.Fatalln("Error:", err)
	}

	body, _ := ioutil.ReadAll(resp.Body)

	fmt.Println("Response")
	fmt.Printf("Status: %v %v\n", resp.StatusCode, http.StatusText(resp.StatusCode))
	fmt.Printf("Body: %v\n", string(body))
}
