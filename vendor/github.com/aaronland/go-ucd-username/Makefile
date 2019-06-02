fmt:
	go fmt *.go
	go fmt cmd/*.go
	go fmt http/*.go

tools: 	
	go build -o bin/ucd-username cmd/ucd-username/main.go
	go build -o bin/ucd-usernamed cmd/ucd-usernamed/main.go

wasm:   
	GOARCH=wasm GOOS=js go build -o www/ucd.wasm cmd/ucd-wasm/main.go

docker-build:
	docker build -t ucd-username .

docker-debug: docker-build
	docker run -it -p 6161:8080 -e HOST='0.0.0.0' ucd-username
