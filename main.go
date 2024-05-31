package main

import (
	"context"
	"fmt"

	badger "github.com/dgraph-io/badger/v4"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/routing"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	"golang.org/x/crypto/bcrypt"
)

var hostNode host.Host
var idht *dht.IpfsDHT
var db *badger.DB

func main() {

	initHost("bvvinai", "bvvinai@1357")
	fmt.Println(hostNode.ID())
	fmt.Println("Listening on : ", hostNode.Addrs())
	connectToPeer("12D3KooWQ484Vs8UEvaAGN7ap7By2sHEkeJMC32DSYxveXgs31Jh")

	select {}
}

func connectToPeer(peerid string) {

	// peerID, err := peer.Decode(peerid)
	// if err != nil {
	// 	panic(err)
	// }

	// for _, p := range host.Peerstore().Peers() {
	// 	if p == peerID {
	// 		fmt.Println("Found peer : ", peerID)
	// 	}
	// }

	// peerAddr, err := idht.FindPeer(context.Background(), peerID)
	// if err != nil {
	// 	panic(err)
	// }
	// if err := host.Connect(context.Background(), peerAddr); err != nil {
	// 	panic(err)
	// }

	// fmt.Println("Connected to remote peer:", peerid)
}

func initHost(username string, password string) {

	db, _ = badger.Open(badger.DefaultOptions("./badger"))

	var hostKey crypto.PrivKey
	get_err := db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte("priv"))
		if err != nil {
			return err
		}
		err = item.Value(func(val []byte) error {
			hostKey, err = crypto.UnmarshalPrivateKey(val)
			return nil
		})
		return err
	})

	if get_err != nil || hostKey == nil {
		fmt.Println(get_err)

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			panic(err)
		}

		priv, _, err := crypto.GenerateKeyPair(
			crypto.Ed25519,
			-1,
		)
		if err != nil {
			panic(err)
		}
		privBytes, err := crypto.MarshalPrivateKey(priv)
		if err != nil {
			panic(err)
		}

		hostNode, _ = libp2p.New(
			libp2p.Identity(hostKey),
			libp2p.NATPortMap(),
			libp2p.Routing(func(h host.Host) (routing.PeerRouting, error) {
				idht, _ = dht.New(context.Background(), h)
				if err := idht.Bootstrap(context.Background()); err != nil {
					panic(err)
				}
				return idht, nil
			}),
			libp2p.EnableNATService(),
			libp2p.EnableRelayService(),
			libp2p.EnableRelay(),
		)

		for _, addr := range dht.DefaultBootstrapPeers {
			pi, _ := peer.AddrInfoFromP2pAddr(addr)
			fmt.Println(pi)
			err := hostNode.Connect(context.Background(), *pi)
			if err != nil {
				fmt.Println(err)
			}
		}

		dhtDiscovery := drouting.NewRoutingDiscovery(idht)
		go func() {
			for {
				_, err := dhtDiscovery.Advertise(context.Background(), "chatapp-bvvinai")
				if err != nil {
					panic(err)
				}

				peerChan, err := dhtDiscovery.FindPeers(context.Background(), "chatapp-bvvinai")
				if err != nil {
					panic(err)
				}

				for peer := range peerChan {
					fmt.Printf("Discovered peer: %s \n", peer.ID)
				}
			}
		}()

		txn := db.NewTransaction(true)
		defer txn.Discard()

		txn.Set([]byte("username"), []byte(username))
		txn.Set([]byte("password"), hashedPassword)
		txn.Set([]byte("priv"), privBytes)
		txn.Set([]byte("peerid"), []byte(hostNode.ID()))
		txn.Commit()
	} else {
		hostNode, _ = libp2p.New(
			libp2p.Identity(hostKey),
			libp2p.NATPortMap(),
			libp2p.Routing(func(h host.Host) (routing.PeerRouting, error) {
				idht, _ = dht.New(context.Background(), h)
				if err := idht.Bootstrap(context.Background()); err != nil {
					panic(err)
				}
				return idht, nil
			}),
			libp2p.EnableNATService(),
			libp2p.EnableRelayService(),
			libp2p.EnableRelay(),
		)

		for _, addr := range dht.DefaultBootstrapPeers {
			pi, _ := peer.AddrInfoFromP2pAddr(addr)
			fmt.Println(pi)
			err := hostNode.Connect(context.Background(), *pi)
			if err != nil {
				fmt.Println(err)
			}
		}

		dhtDiscovery := drouting.NewRoutingDiscovery(idht)
		go func() {
			for {
				_, err := dhtDiscovery.Advertise(context.Background(), "chatapp-bvvinai")
				if err != nil {
					panic(err)
				}

				peerChan, err := dhtDiscovery.FindPeers(context.Background(), "chatapp-bvvinai")
				if err != nil {
					panic(err)
				}

				for peer := range peerChan {
					fmt.Printf("Discovered peer: %s \n", peer.ID)
				}
			}
		}()
	}
}
