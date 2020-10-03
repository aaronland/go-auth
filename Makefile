cli:
	go build -mod vendor -o bin/add-account cmd/add-account/main.go
	go build -mod vendor -o bin/totp-code cmd/totp-code/main.go
	go build -mod vendor -o bin/auth-server cmd/auth-server/main.go

debug:
	go run -mod vendor cmd/auth-server/main.go  -accounts-uri fs://./tmp -sessions-uri fs://./tmp -crumb-uri debug -session-cookie-uri 'http://localhost:8080/?name=s&ttl=PT1H'
