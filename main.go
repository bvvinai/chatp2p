package main

import (
	"fmt"
	"net"
)

func main() {
	serverAddr, err := net.ResolveUDPAddr("udp", "54.167.69.227:53")
	if err != nil {
		fmt.Println("Error resolving server address:", err.Error())
		return
	} else {
		fmt.Println(serverAddr)
	}

	serverConn, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		return
	} else {
		fmt.Println(serverConn)
	}
	defer serverConn.Close()

	fmt.Println("Server started")

	go func() {
		buffer := make([]byte, 1024)
		for {
			n, addr, err := serverConn.ReadFromUDP(buffer)
			if err != nil {
				fmt.Println("Error reading:", err.Error())
				continue
			}
			fmt.Printf("Received message from %s: %s\n", addr, string(buffer[:n]))
		}
	}()

	// Start UDP client
	clientAddr, err := net.ResolveUDPAddr("udp", "localhost:0")
	if err != nil {
		fmt.Println("Error resolving client address:", err.Error())
		return
	}

	clientConn, err := net.DialUDP("udp", nil, clientAddr)
	if err != nil {
		fmt.Println("Error connecting:", err.Error())
		return
	}
	defer clientConn.Close()

	// Send message to server
	message := []byte("Hello from client")
	_, err = clientConn.Write(message)
	if err != nil {
		fmt.Println("Error sending:", err.Error())
		return
	}
	fmt.Println("Message sent")
	select {}
}
