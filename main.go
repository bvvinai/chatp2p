package main

import (
	"context"
	"fmt"
	"time"

	badger "github.com/dgraph-io/badger/v4"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"golang.org/x/crypto/bcrypt"
)

//const chatProtocolID = "/chat/1.0.0"

func main() {

	db, err := badger.Open(badger.DefaultOptions("./badger"))
	if err != nil {
		panic(err)
	}
	defer db.Close()

	host, dht := initHost(db, "bvvinai", "bvvinai@1357")
	defer host.Close()
	defer dht.Close()
	fmt.Println(host.ID())
	//connectToPeer(host, dht, "12D3KooWQ484Vs8UEvaAGN7ap7By2sHEkeJMC32DSYxveXgs31Jh")

	select {}
}

func connectToPeer(h host.Host, dht *dht.IpfsDHT, peerid string) {
	// routingDiscovery := routing.NewRoutingDiscovery(dht)
	// peerChan, err := routingDiscovery.FindPeers(context.Background(), "meet me here vinai")
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Println(peerChan)

	peerID, err := peer.Decode(peerid)
	if err != nil {
		panic(err)
	}
	peerInfo, err := dht.FindPeer(context.Background(), peerID)
	if err != nil {
		panic(err)
	}
	if err := h.Connect(context.Background(), peerInfo); err != nil {
		panic(err)
	}

	fmt.Println("Connected to remote peer:", peerid)
}

func initHost(db *badger.DB, username string, password string) (host.Host, *dht.IpfsDHT) {

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

		host, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/13000"), libp2p.Identity(priv))
		if err != nil {
			panic(err)
		}
		defer host.Close()

		txn := db.NewTransaction(true)
		defer txn.Discard()

		txn.Set([]byte("username"), []byte(username))
		txn.Set([]byte("password"), hashedPassword)
		txn.Set([]byte("priv"), privBytes)
		txn.Set([]byte("peerid"), []byte(host.ID()))
		txn.Commit()
		bootstrapPeers := make([]peer.AddrInfo, len(dht.DefaultBootstrapPeers))
		for i, addr := range dht.DefaultBootstrapPeers {
			peerinfo, _ := peer.AddrInfoFromP2pAddr(addr)
			bootstrapPeers[i] = *peerinfo
		}
		dht, err := dht.New(context.Background(), host, dht.BootstrapPeers(bootstrapPeers...))
		if err != nil {
			panic(err)
		}
		if err := dht.Bootstrap(context.Background()); err != nil {
			panic(err)
		}
		return host, dht
	} else {
		host, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/13000"), libp2p.Identity(hostKey))
		if err != nil {
			panic(err)
		}
		dht, err := dht.New(context.Background(), host)
		if err != nil {
			panic(err)
		}
		if err := dht.Bootstrap(context.Background()); err != nil {
			panic(err)
		}
		time.Sleep(5 * time.Second)
		// routingDiscovery := routing.NewRoutingDiscovery(dht)
		// dutil.Advertise(context.Background(), routingDiscovery, "unanimous-chat-app")
		return host, dht
	}
}
