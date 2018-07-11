package main

import (
    "fmt"
    "html"
    "log"
    "net/http"
)

func main() {

    // http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    //     fmt.Fprintf(w, "Hello, %q", html.EscapeString(r.URL.Path))
    //     fmt.Println("hello: %q",html.EscapeString(r.URL.Path))
    // })

    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, "Hello, %q", html.EscapeString(r.URL.Path))
        fmt.Println("hello: %q",html.EscapeString(r.URL.Path))
    })
    
    http.HandleFunc("/hi", func(w http.ResponseWriter, r *http.Request){
        fmt.Fprintf(w, "Hi")
    })

    log.Fatal(http.ListenAndServeTLS("0.0.0.0:8081", "www.evn2.com.cert.pem", "www.env2.com.key.pem",nil))
    // log.Fatal(http.ListenAndServe("0.0.0.0:8081",nil))
}