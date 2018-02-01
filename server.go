
package main

import (
    _ "fmt"
    "net/http"
    "encoding/json"
    //_ "html/tmplate"
)

type Issue struct {
	Number int
	Url string `json:"html_url"`
	Title string
}

func handler(w http.ResponseWriter, r *http.Request) {
	var iss = []Issue{
		Issue{Number:1,Url:"123",Title:"t1"},
		
	}

	json.NewEncoder(w).Encode(iss)
    //fmt.Fprintf(w,
      //  "Hi, This is an example of http service in golang!")
}

func main() {
    http.HandleFunc("/", handler)
    http.ListenAndServe(":8080", nil)
    //http.ListenAndServeTLS(":8081", "server.crt",
    //                       "server.key", nil)
}
