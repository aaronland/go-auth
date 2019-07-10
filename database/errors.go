package database

func IsNotExist(e error) bool {

	switch e.(type) {
	case *ErrNoAccount:
		return true
	case *ErrNoToken:
		return true
	default:
		return false
	}
}

type ErrNoAccount struct {
	error
}

func (e *ErrNoAccount) String() string {
	return e.Error()
}

func (e *ErrNoAccount) Error() string {
	return "Account does not exist"
}

type ErrNoToken struct {
	error
}

func (e *ErrNoToken) String() string {
	return e.Error()
}

func (e *ErrNoToken) Error() string {
	return "Token does not exist"
}
