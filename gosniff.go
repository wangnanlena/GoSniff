package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"gopkg.in/urfave/cli.v2"
)

var (
	device       string = "wlp4s0"
	suck         string = "tcp and port 443"
	snapshot_len int32  = 65535
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = -1 * time.Second
	handle       *pcap.Handle
	sniffdump    string
)

func main() {
	app := &cli.App{
		Name:      "gosniff",
		Version:   "0.0.1",
		UsageText: "gosniff --interface eth0 --sniff \"tcp and port 80\"",
		Authors: []*cli.Author{
			{
				Name:  "Fernandez,Chris ReK2",
				Email: "cfernandez@protonmail.ch"},
		},
		Flags: []cli.Flag{

			&cli.StringFlag{
				Name:        "interface",
				Aliases:     []string{"i"},
				Value:       "eth0",
				Usage:       "the interface to use",
				Destination: &device,
			},
			&cli.StringFlag{
				Name:    "file",
				Aliases: []string{"f"},
				//Value:       "sniffdump",
				Usage:       "To log create a pcap with sniff dump",
				Destination: &sniffdump,
			},
			&cli.BoolFlag{
				Name:    "promiscuous",
				Aliases: []string{"p"},
				//Value:       "false",
				Usage:       "To enable promiscuous mode",
				Destination: &promiscuous,
			},
			&cli.StringFlag{
				Name:        "sniff",
				Aliases:     []string{"s"},
				Value:       "tcp and port 443",
				Usage:       "the BPF syntax parameters to sniff on",
				Destination: &suck,
			},
		},
		Action: func(c *cli.Context) error {
			fmt.Printf("Capturing on Interface %v\n", c.String("interface"))
			fmt.Printf("Promiscuous mode: %v\n", c.String("promiscuous"))
			sniff(device, suck, sniffdump)
			return nil
		},
		Commands: []*cli.Command{
			{
				Name:        "list-interfaces",
				Aliases:     []string{"l"},
				Usage:       "sniff list-interfaces/sniff l",
				Description: "list interfaces",
				Action: func(c *cli.Context) error {
					fmt.Printf("listing interfaces:  ")
					list_int()
					return nil
				},
			},
		},
	}
	app.Run(os.Args)
}

func sniff(device string, suck string, sniffdump string) string {

	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Set filter
	err = handle.SetBPFFilter(suck)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Capturing: ", suck)

	// Process packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		fmt.Println(packet)
		//if capture to pcap file enable then file_cap(packet) etc
	}
	return device
}

func list_int() {
	var devices []pcap.Interface
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(devices)
}

func file_cap() {
}
