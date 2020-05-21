package api

import "fmt"

type version struct {
	year  uint
	month uint
	patch uint
}

func (v version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.year, v.month, v.patch)
}

var Version = version{
	year:  20,
	month: 05,
	patch: 5,
}
