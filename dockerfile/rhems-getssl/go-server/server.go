package main

import (
	"fmt"
	"net/http"
	"os"
)

type Page struct {
	Title string
	Count int
}

func viewHandler(w http.ResponseWriter, r *http.Request) {
	uri := r.URL.Path[1:]
	fmt.Fprintln(os.Stdout, "URI: ", uri)
	fmt.Fprintln(os.Stdout, "File validation")
	fileName := os.Getenv("FILE_NAME")
	bytes, err := os.ReadFile("acme-challenge/" + fileName)
	if err != nil {
		panic(err)
	}

	w.Write(bytes)
}

func healthcheckHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(os.Stdout, "Healthcheck")
	w.Write([]byte("ok"))
}

func main() {
	fileName := os.Getenv("FILE_NAME")
	fmt.Fprintln(os.Stdout, "File name: ", fileName)
	fmt.Fprintln(os.Stdout, "/.well-known/acme-challenge/"+fileName)
	http.HandleFunc("/.well-known/acme-challenge/"+fileName, viewHandler)
	http.HandleFunc("/{$}", healthcheckHandler)
	http.ListenAndServe(":80", nil)
}
