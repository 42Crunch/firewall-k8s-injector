package main

import (
	"fmt"
	"os"

	"github.com/42crunch/kubernetes-injector/cmd"
)

func main() {
	if err := cmd.RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}
