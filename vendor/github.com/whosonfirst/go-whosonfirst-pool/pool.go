package pool

import (
	"strconv"
)

type Item interface {
	String() string
	Int() int64
}

func NewIntItem(i int64) Item {

     return &Int{ int: i }
}

func NewStringItem(s string) Item {

     return &String{ string: s }
}

type Int struct {
	Item
	int int64
}

func (i Int) String() string {
	return strconv.FormatInt(i.int, 10)
}

func (i Int) Int() int64 {
	return i.int
}

type String struct {
	Item
	string string
}

func (s String) String() string {
	return s.string
}

func (s String) Int() int64 {
	return int64(0)
}

type LIFOPool interface {
	Length() int64
	Push(Item)
	Pop() (Item, bool)
}
