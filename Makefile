CWD=$(shell pwd)
GOPATH := $(CWD)

prep:
	if test -d pkg; then rm -rf pkg; fi

self:   prep rmdeps
	if test -d src; then rm -rf src; fi
	mkdir -p src/github.com/aaronland/go-auth

rmdeps:
	if test -d src; then rm -rf src; fi 

build:	fmt bin

deps:
	@GOPATH=$(GOPATH) go get -u "github.com/boltdb/bolt"
	@GOPATH=$(GOPATH) go get -u "github.com/aaronland/go-ucd-username"
	@GOPATH=$(GOPATH) go get -u "github.com/aaronland/go-string"
	@GOPATH=$(GOPATH) go get -u "github.com/aaronland/go-secretbox"