package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {

	var (
		iface           = flag.String("i", "eth0", "interface to capture packets on")
		trafficPort     = flag.Int("s", 8080, "select TCP or UDP packets via this port (traffic to encapsulate)")
		destinationIP   = flag.String("d", "", "destination IP")
		destinationPort = flag.Int("p", 6081, "destination port")
	)

	flag.Parse()

	if *destinationIP == "" {
		log.Fatalf("destination IP is required")
	}

	// Open a live packet capture handle
	handle, err := pcap.OpenLive(*iface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("could not use capture device: %v", err)
	}
	defer handle.Close()

	// Create a UDP address for the destination
	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", *destinationIP, *destinationPort))
	if err != nil {
		log.Printf("Failed to resolve UDP address: %v", err)
		return
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		log.Printf("Failed to dial UDP: %v", err)
		return
	}
	defer conn.Close()

	geneveHeader := &GeneveHeader{
		version:       0,
		optionsLength: 0,
		OBit:          0,
		CBit:          0,
		protocolType:  0x6558,
		VNI:           0xa701,
		reserved:      0,
	}

	serializedGeneveHeader := geneveHeader.Serialize()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if networkLayer := packet.NetworkLayer(); networkLayer != nil {
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				if tcp.DstPort != layers.TCPPort(*trafficPort) && tcp.SrcPort != layers.TCPPort(*trafficPort) {
					continue
				}
			} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
				udp, _ := udpLayer.(*layers.UDP)
				if udp.DstPort != layers.UDPPort(*trafficPort) && udp.SrcPort != layers.UDPPort(*trafficPort) {
					continue
				}
			} else {
				// fmt.Println("Unknown packet:")
				// for _, layer := range packet.Layers() {
				// 	fmt.Println("\tlayer: ", layer.LayerType())
				// }
				continue
			}

			// fmt.Println("IP packet: ")
			// for _, layer := range packet.Layers() {
			// 	fmt.Println("\tlayer: ", layer.LayerType())
			// }

			encapsulatedPacket := append(serializedGeneveHeader, packet.Data()...)

			// Send the packet to the destination
			_, err := conn.Write(encapsulatedPacket)
			if err != nil {
				log.Printf("Failed to send packet: %v", err)
				return
			}
		}
	}
}

type GeneveHeader struct {
	version       uint8
	optionsLength uint8
	OBit          uint8
	CBit          uint8
	protocolType  uint16
	VNI           uint32
	reserved      uint8
}

// https://www.rfc-editor.org/rfc/rfc8926.html#name-geneve-packet-format-over-i
func (g *GeneveHeader) Serialize() []byte {
	return []byte{
		(g.version << 6) | g.optionsLength,
		(g.OBit << 7) | (g.CBit << 6),
		uint8(g.protocolType >> 8),
		uint8(g.protocolType),
		uint8(g.VNI >> 16),
		uint8(g.VNI >> 8),
		uint8(g.VNI),
		g.reserved,
	}
}
