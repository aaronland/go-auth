# go-whosonfirst-pool

A generic LIFO pool derived from Simon Waldherr's [example code](https://github.com/SimonWaldherr/golang-examples/blob/2be89f3185aded00740a45a64e3c98855193b948/advanced/lifo.go). This implementation is safe to use with goroutines.

## Usage

### Simple

```
import (
       "fmt"
       "github.com/whosonfirst/go-whosonfirst-pool"
)

func main() {

     p := pool.NewMemLIFOPool()
     i := pool.NewIntItem(int64(123))

     p.Push(i)
     v, ok := p.Pop()

     if ok {
     	fmt.Printf("%d", v.Int())
     }
}
```
 
## See also

* https://github.com/SimonWaldherr/golang-examples/blob/2be89f3185aded00740a45a64e3c98855193b948/advanced/lifo.go
