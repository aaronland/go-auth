cli:
	go build -mod vendor -o bin/add-account cmd/add-account/main.go
	go build -mod vendor -o bin/totp-code cmd/totp-code/main.go
	go build -mod vendor -o bin/auth-server cmd/auth-server/main.go

debug:
	go run -mod vendor cmd/auth-server/main.go  -accounts-uri fs://./tmp -sessions-uri fs://./tmp -crumb-uri debug

debug-code:
	go run -mod vendor cmd/totp-code/main.go -accounts-uri fs://./tmp -email $(EMAIL)

cookie-test:
	go run -mod vendor cmd/cookie-test/main.go
