CWD=$(shell pwd)
GOPATH := $(CWD)

OS := $(shell uname -s | tr '[:upper:]' '[:lower:]')

ifeq ($(OSTYPE), android)
	OS:= $(OSTYPE)
endif

prep:
	if test -d pkg; then rm -rf pkg; fi

self:   prep rmdeps
	if test ! -d src; then mkdir src; fi
	mkdir -p src/github.com/aaronland/go-secretbox
	cp -r config src/github.com/aaronland/go-secretbox/
	cp -r salt src/github.com/aaronland/go-secretbox/
	cp *.go src/github.com/aaronland/go-secretbox/
	cp -r vendor/* src/

rmdeps:
	if test -d src; then rm -rf src; fi 

build:	fmt bin

deps:
	@GOPATH=$(GOPATH) go get -u "golang.org/x/crypto/nacl/secretbox"
	@GOPATH=$(GOPATH) go get -u "golang.org/x/crypto/scrypt"
	@GOPATH=$(GOPATH) go get -u "golang.org/x/crypto/ssh/terminal"
	@GOPATH=$(GOPATH) go get -u "github.com/aaronland/go-string"

vendor-deps: rmdeps deps
	if test ! -d vendor; then mkdir vendor; fi
	if test -d vendor; then rm -rf vendor; fi
	cp -r src vendor
	find vendor -name '.git' -print -type d -exec rm -rf {} +
	rm -rf src

fmt:
	go fmt cmd/*.go
	go fmt config/*.go
	go fmt salt/*.go
	go fmt *.go

bin: 	self
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

compile: self
	if test ! -d bin/$(OS); then mkdir -p bin/$(OS); fi
	@GOPATH=$(GOPATH) GOOS=$(OS) GOARCH=386 go build -o bin/$(OS)/secretbox cmd/secretbox.go
	@GOPATH=$(GOPATH) GOOS=$(OS) GOARCH=386 go build -o bin/$(OS)/saltshaker cmd/saltshaker.go
