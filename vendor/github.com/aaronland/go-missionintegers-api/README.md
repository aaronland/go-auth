# go-missionintegers-api

Go package for the Mission Integers API.

## Install

You will need to have both `Go` and the `make` programs installed on your computer. Assuming you do just type:

```
make bin
```

All of this package's dependencies are bundled with the code in the `vendor` directory.

## Usage

## Simple

```
package main

import (
	"fmt"
	"github.com/aaronland/go-missionintegers-api"
)

func main() {

	client := api.NewAPIClient()
	i, _ := client.NextInt()

	fmt.Println(i)
}
```

## Tools

### int

Mint one or more Mission Integers.

```
$> ./bin/int -h
Usage of ./bin/int:
  -count int
    	The number of Mission Integers to mint (default 1)
```

## See also

* https://missionintegers.com/
* https://github.com/aaronland/go-artisanal-integers
