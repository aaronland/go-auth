package main

import (
	"fmt"
	"net/http"
	"log"
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

func NoopHandler(next http.Handler) http.Handler {

	fn := func(rsp http.ResponseWriter, req *http.Request) {

		log.Println("NO OP", req.URL.Path, req.Method)
		
		next.ServeHTTP(rsp, req)
		return		
	}

	return http.HandlerFunc(fn)	
}

func RemoveFirstHandler(next http.Handler) http.Handler {

	fn := func(rsp http.ResponseWriter, req *http.Request) {

		log.Println("REMOVE 1", req.URL.Path, req.Method)
		
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

		log.Println("REMOVE 2", req.URL.Path, req.Method)
		
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

		log.Println("REDIRECT", req.URL.Path, req.Method)
		http.Redirect(rsp, req, "/", 303)
		return		
	}

	return http.HandlerFunc(fn)		
}

func IndexHandler() http.Handler {

	fn := func(rsp http.ResponseWriter, req *http.Request) {

		rsp.Header().Set("Content-type", "text/html")

		c1, err1 := req.Cookie("c1")
		c2, err2 := req.Cookie("c2")

		fmt.Fprintf(rsp, "C1 '%s' %v <br />", c1.String(), err1)
		fmt.Fprintf(rsp, "C2 '%s' %v <br />", c2.String(), err2)		

		if err1 == nil && err2 == nil {
			rsp.Write([]byte(`<form method="POST" action="/remove"><button type="submit">remove</button></form>`))
		} else {
			rsp.Write([]byte(`<a href="/add">add</a>`))
		}
		
		return
	}

	return http.HandlerFunc(fn)		
}

func main() {

	mux := http.NewServeMux()

	mux.Handle("/", NoopHandler(NoopHandler(IndexHandler())))
	mux.Handle("/add", NoopHandler(NoopHandler(AddHandler(RewriteHandler()))))
	mux.Handle("/remove", NoopHandler(NoopHandler(RemoveFirstHandler(RemoveSecondHandler(RewriteHandler())))))

	http.ListenAndServe(":8080", mux)
}
