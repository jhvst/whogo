package main

import (
	"fmt"
	"github.com/9uuso/whogo"
	"os"
	"time"
)

func main() {

	if len(os.Args) <= 1 {
		fmt.Println("Domain not specified. Exiting.")
		os.Exit(1)
	}
	host := os.Args[1]

	status, err := whogo.Whois(host, 3*time.Second)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(string(status))

	if whogo.Available(status) {
		fmt.Println("available")
		os.Exit(0)
	}
	fmt.Println("not available")

}
