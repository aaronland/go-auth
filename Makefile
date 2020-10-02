cli:
	go build -mod vendor -o bin/add-account cmd/add-account/main.go
	go build -mod vendor -o bin/totp-code cmd/totp-code/main.go
	go build -mod vendor -o bin/auth-server cmd/auth-server/main.go

debug:
	go run -mod vendor cmd/auth-server/main.go  -accounts-uri fs://./tmp -auth-cookie-uri debug -crumb-uri debug -mfa-cookie-uri debug -templates './templates/*.html'
