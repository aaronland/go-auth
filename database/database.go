package database

func IsNotExist(e error) bool {

	switch e.(type) {
	case *ErrNoAccount, ErrNoAccount:
		return true
	case *ErrNoToken, ErrNoToken:
		return true
	default:
		return false
	}
}
