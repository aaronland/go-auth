package uid

func NewNullUID() (UID, error) {
	return NewStringUID("null")
}
