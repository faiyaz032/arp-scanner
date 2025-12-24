package main

import (
	"log"

	"github.com/faiyaz032/arp-scanner/pkg"
)

func main() {
	iface, err := pkg.GetActiveInterface()
	if err != nil {
		log.Fatal(err)
		return
	}

}
