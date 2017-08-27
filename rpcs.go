package main

import (
        "fmt"
        _ "html"
        "log"
        "net/http"
        "encoding/json"
)
type structtest struct {
	str1 string
	str2 string
}
func main() {
        http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
            //fmt.Fprintf(w, "Hello, %q", html.EscapeString(r.URL.Path))
            k := structtest{"A","B"} 
            fmt.Printf("%v(%v)\n",k, r)
            json.NewEncoder(w).Encode(k)
    })

    log.Fatal(http.ListenAndServe(":8080", nil))
}