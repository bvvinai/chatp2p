package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/libp2p/go-libp2p"
	"github.com/multiformats/go-multiaddr"
)

const chatProtocolID = "/chat/1.0.0"

func main() {
	node, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"))
	if err != nil {
		panic(err)
	}
	defer node.Close()
	fmt.Println(node.ID(), " : ", node.Addrs())

	peerMA, err := multiaddr.NewMultiaddr(node.Addrs()[0].String())
	if err != nil {
		panic(err)
	}
	fmt.Println(peerMA)

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	fmt.Println("Received signal, shutting down...")
}
