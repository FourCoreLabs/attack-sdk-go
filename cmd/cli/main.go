package main

import (
	"log"

	"github.com/fourcorelabs/attack-sdk-go/cmd/cli/cmd" // Adjusted import path
)

func main() {
	if err := cmd.Execute(); err != nil {
		log.Fatalf("Error executing command: %v", err)
	}
}
