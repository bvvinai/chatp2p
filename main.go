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
	"github.com/libp2p/go-libp2p/core/routing"
	drouter "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	dutil "github.com/libp2p/go-libp2p/p2p/discovery/util"
	"github.com/libp2p/go-libp2p/p2p/net/connmgr"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	libp2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
	"golang.org/x/crypto/bcrypt"
)

//const chatProtocolID = "/chat/1.0.0"

func main() {

	db, err := badger.Open(badger.DefaultOptions("./badger"))
	if err != nil {
		panic(err)
	}
	defer db.Close()

	host, dhti, rd := initHost(db, "bvvinai", "bvvinai@1357")
	defer host.Close()
	defer dhti.Close()
	fmt.Println(host.ID())
	fmt.Println("Listening on : ", host.Addrs())
	connectToPeer(host, dhti, rd, "12D3KooWQfBE9wUrCNvk81vw8a3vho8sBKG9DRoA9WwKSd9bUNGW")

	select {}
}

func connectToPeer(h host.Host, dhti *dht.IpfsDHT, rd *drouter.RoutingDiscovery, peerid string) {

	peerChan, err := rd.FindPeers(context.Background(), peerid)
	if err != nil {
		panic(err)
	}
	for peer := range peerChan {
		fmt.Println("Found peer:", peer)
	}

	// peerID, err := peer.Decode(peerid)
	// if err != nil {
	// 	panic(err)
	// }
	// peerAddr, err := peer.AddrInfoFromString("/ip4/54.209.93.91/tcp/50805/p2p/" + peerid)
	// if err != nil {
	// 	panic(err)
	// }
	// if err := h.Connect(context.Background(), *peerAddr); err != nil {
	// 	panic(err)
	// }

	// fmt.Println("Connected to remote peer:", peerid)
}

func initHost(db *badger.DB, username string, password string) (host.Host, *dht.IpfsDHT, *drouter.RoutingDiscovery) {

	connmgr, err := connmgr.NewConnManager(
		100,
		400,
		connmgr.WithGracePeriod(time.Minute),
	)
	if err != nil {
		panic(err)
	}
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
		dht, err := dht.New(context.Background(), host)
		if err != nil {
			panic(err)
		}
		if err := dht.Bootstrap(context.Background()); err != nil {
			panic(err)
		}
		return host, dht, nil
	} else {
		var dhti *dht.IpfsDHT
		host, err := libp2p.New(
			libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/12000"),
			libp2p.Identity(hostKey),
			libp2p.ConnectionManager(connmgr),
			libp2p.EnableNATService(),
			libp2p.NATPortMap(),
			libp2p.Security(libp2ptls.ID, libp2ptls.New),
			libp2p.Security(noise.ID, noise.New),
			libp2p.Routing(func(h host.Host) (routing.PeerRouting, error) {
				dhti, err = dht.New(context.Background(), h)
				if err != nil {
					return nil, err
				}

				if err := dhti.Bootstrap(context.Background()); err != nil {
					panic(err)
				}
				return dhti, nil
			}),
		)
		if err != nil {
			panic(err)
		}

		routingDiscovery := drouter.NewRoutingDiscovery(dhti)
		dutil.Advertise(context.Background(), routingDiscovery, string(host.ID().String()))
		return host, dhti, routingDiscovery
	}
}
