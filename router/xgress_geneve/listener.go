/*
	Copyright 2019 NetFoundry, Inc.

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package xgress_geneve

import (
	"log"
	"net"
	"syscall"

	"github.com/openziti/fabric/router/xgress"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type listener struct{}

func (self *listener) Listen(string, xgress.BindHandler) error {
	go func() {
		// Open UDP socket to listen for Geneve Packets
		conn, err := net.ListenPacket("udp", ":6081")
		if err != nil {
			log.Printf("geneve decapsulation, exiting: %v", err)
			panic(err)
		}
		// Close it when done
		defer conn.Close()
		// Open a raw socket to send Modified Packets to Networking Stack
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
		if err != nil {
			log.Printf("Fail to open Socket :%v\n", err)
			panic(err)
		}
		// Close it when done
		defer syscall.Close(fd)
		// Loop to process packets
		for {
			buf := make([]byte, 9000)
			n, _, _ := conn.ReadFrom(buf)
			if err != nil {
				log.Printf("error reading from buffer, exiting: %v", err)
				panic(err)
			}
			// Remove Geneve layer
			packet := gopacket.NewPacket(buf[:n], layers.LayerTypeGeneve, gopacket.DecodeOptions{NoCopy: true})
			// Extract IP Headers and Payload
			networkHeaders := packet.NetworkLayer().LayerContents()
			networkPayload := packet.NetworkLayer().LayerPayload()
			modifiedPacket := append(networkHeaders, networkPayload...)
			// Get Destination IP from the IP Header
			var array4byte [4]byte
			copy(array4byte[:], buf[56:60])
			sockAddress := syscall.SockaddrInet4{
				Port: 0,
				Addr: array4byte,
			}
			// Send the new packet to be routed to Ziti TProxy
			err = syscall.Sendto(fd, modifiedPacket, 0, &sockAddress)
			if err != nil {
				log.Printf("Failed to send modified packet to Socket: %v\n", err)
			}
		}
	}()
	return nil
}

func (self *listener) Close() error {
	return nil
}
