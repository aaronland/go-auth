package main

import (
	"fmt"
	"net/http"
)

func AddHandler(next http.Handler) http.Handler {

	fn := func(rsp http.ResponseWriter, req *http.Request) {

		ck1 := &http.Cookie{
			Name: "c1",
			Path: "/",
			Value: "first cookie",
		}

		ck2 := &http.Cookie{
			Name: "c2",
			Path: "/",
			Value: "second cookie",
		}
		
		http.SetCookie(rsp, ck1)
		http.SetCookie(rsp, ck2)

		next.ServeHTTP(rsp, req)		
		return
	}

	return http.HandlerFunc(fn)	
}

func RemoveHandler() http.Handler {

	fn := func(rsp http.ResponseWriter, req *http.Request) {

		ck1 := &http.Cookie{
			Name: "c1",
			Path: "/",
			Value: "",
			MaxAge: -1,			
		}

		ck2 := &http.Cookie{
			Name: "c2",
			Path: "/",
			Value: "",
			MaxAge: -1,
		}
		
		http.SetCookie(rsp, ck1)
		http.SetCookie(rsp, ck2)
		
		rsp.Write([]byte("REMOVE"))
		return		
	}

	return http.HandlerFunc(fn)	
}

func RemoveFirstHandler(next http.Handler) http.Handler {

	fn := func(rsp http.ResponseWriter, req *http.Request) {

		ck1 := &http.Cookie{
			Name: "c1",
			Path: "/",
			Value: "",
			MaxAge: -1,			
		}

		http.SetCookie(rsp, ck1)
		
		next.ServeHTTP(rsp, req)
		return		
	}

	return http.HandlerFunc(fn)	
}

func RemoveSecondHandler(next http.Handler) http.Handler {

	fn := func(rsp http.ResponseWriter, req *http.Request) {

		ck2 := &http.Cookie{
			Name: "c2",
			Path: "/",
			Value: "",
			MaxAge: -1,
		}
		
		http.SetCookie(rsp, ck2)

		next.ServeHTTP(rsp, req)
		return		
	}

	return http.HandlerFunc(fn)	
}

func RewriteHandler() http.Handler {

	fn := func(rsp http.ResponseWriter, req *http.Request) {
		http.Redirect(rsp, req, "/", 303)
		return		
	}

	return http.HandlerFunc(fn)		
}

func IndexHandler() http.Handler {

	fn := func(rsp http.ResponseWriter, req *http.Request) {

		c1, err1 := req.Cookie("c1")
		c2, err2 := req.Cookie("c2")

		fmt.Fprintf(rsp, "C1 '%s' %v\n", c1.String(), err1)
		fmt.Fprintf(rsp, "C2 '%s' %v\n", c2.String(), err2)		

		return
	}

	return http.HandlerFunc(fn)		
}

func main() {

	mux := http.NewServeMux()

	mux.Handle("/", IndexHandler())
	mux.Handle("/add", AddHandler(RewriteHandler()))
	mux.Handle("/remove", RemoveFirstHandler(RemoveSecondHandler(RewriteHandler())))	

	http.ListenAndServe(":8080", mux)
}
