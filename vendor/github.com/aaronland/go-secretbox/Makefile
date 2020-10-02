CWD := $(shell pwd)
OS := $(shell uname -s | tr '[:upper:]' '[:lower:]')

tools:
	@make compile
	if test -e bin/secretbox; then rm bin/secretbox; fi
	if test -e bin/saltshaker; then rm bin/saltshaker; fi
	ln -s $(CWD)/bin/$(OS)/secretbox $(CWD)/bin/secretbox
	ln -s $(CWD)/bin/$(OS)/saltshaker $(CWD)/bin/saltshaker

dist: darwin linux android

darwin:
	@make compile OS=darwin

linux:
	@make compile OS=linux

android:
	@make compile OS=android

# see the way this is pegged at GOARCH=386? yeah that...

compile: 
	GOOS=$(OS) GOARCH=386 go build -o bin/$(OS)/secretbox cmd/secretbox/main.go
	GOOS=$(OS) GOARCH=386 go build -o bin/$(OS)/saltshaker cmd/saltshaker/main.go
