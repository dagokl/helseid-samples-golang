package routes

import (
	"fmt"
	"net/http"
)

func Foo(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "bar")
}
