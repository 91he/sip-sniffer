package main

import (
	"sip-sniffer/src"

	"github.com/guonaihong/clop"
)

func main() {
	if err := clop.Bind(&src.SS); err != nil {
		panic(err)
	}

	src.SS.DoSniff()
}
