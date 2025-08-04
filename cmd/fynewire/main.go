package main

import (
	"log"

	"github.com/arya2004/fynewire/internal/sniffer"
	"github.com/arya2004/fynewire/internal/ui"
)



func main() {
	ifaces, err := sniffer.Interfaces()
	if err != nil {
		log.Fatalf("pcap error: %v", err)
	}

	ui.NewApp().Run(ifaces)
}