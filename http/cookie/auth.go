package cookie

func NewAuthCookie(name string, secret string, salt string) (Cookie, error) {

	return NewEncryptedCookie(name, secret, salt)
}
