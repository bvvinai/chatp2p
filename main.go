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
	"github.com/libp2p/go-libp2p/core/routing"
	"github.com/libp2p/go-libp2p/p2p/net/connmgr"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	libp2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
	"github.com/multiformats/go-multiaddr"
	"golang.org/x/crypto/bcrypt"
)

//const chatProtocolID = "/chat/1.0.0"

func main() {

	db, err := badger.Open(badger.DefaultOptions("./badger"))
	if err != nil {
		panic(err)
	}
	defer db.Close()

	host := initHost(db, "bvvinai", "bvvinai@1357")
	defer host.Close()
	fmt.Println(host.ID())
	fmt.Println("Listening on : ", host.Addrs())
	//connectToPeer(host, "12D3KooWQ484Vs8UEvaAGN7ap7By2sHEkeJMC32DSYxveXgs31Jh")

	select {}
}

func connectToPeer(h host.Host, peerid string) {

	peerID, err := peer.Decode(peerid)
	if err != nil {
		panic(err)
	}
	idht, err := dht.New(context.Background(), h)
	if err != nil {
		panic(err)
	}
	peerAddr, err := idht.FindPeer(context.Background(), peerID)
	if err != nil {
		panic(err)
	}
	if err := h.Connect(context.Background(), peerAddr); err != nil {
		panic(err)
	}

	fmt.Println("Connected to remote peer:", peerid)
}

func initHost(db *badger.DB, username string, password string) host.Host {

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

		host, err := libp2p.New(
			libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/12000"),
			libp2p.Identity(hostKey),
			libp2p.ConnectionManager(connmgr),
			libp2p.EnableNATService(),
			libp2p.NATPortMap(),
			libp2p.Security(libp2ptls.ID, libp2ptls.New),
			libp2p.Security(noise.ID, noise.New),
		)
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

		return host
	} else {
		var idht *dht.IpfsDHT
		host, err := libp2p.New(
			libp2p.Identity(hostKey),
			libp2p.ConnectionManager(connmgr),
			libp2p.Security(libp2ptls.ID, libp2ptls.New),
			libp2p.Security(noise.ID, noise.New),
			libp2p.NATPortMap(),
			libp2p.Routing(func(h host.Host) (routing.PeerRouting, error) {
				idht, err = dht.New(context.Background(), h)
				if err := idht.Bootstrap(context.Background()); err != nil {
					panic(err)
				}
				return idht, err
			}),
			libp2p.EnableNATService(),
			libp2p.EnableRelayService(),
			libp2p.EnableAutoRelayWithStaticRelays([]peer.AddrInfo{
				{
					ID:    peer.ID("12D3KooWSz5iNCtZSoRo3P9ttc5de7zWeMcz8AQpazTqH4A6Z23h"),
					Addrs: []multiaddr.Multiaddr{multiaddr.StringCast("/dns4/ams-3.bootstrap.libp2p.io")},
				},
				{
					ID:    peer.ID("QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa"),
					Addrs: []multiaddr.Multiaddr{multiaddr.StringCast("/dns4/sjc-1.bootstrap.libp2p.io")},
				},
				{
					ID:    peer.ID("QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN"),
					Addrs: []multiaddr.Multiaddr{multiaddr.StringCast("/dns4/nyc-1.bootstrap.libp2p.io")},
				},
			}),
		)
		if err != nil {
			panic(err)
		}

		for _, addr := range dht.DefaultBootstrapPeers {
			pi, _ := peer.AddrInfoFromP2pAddr(addr)
			fmt.Println(pi)
			err := host.Connect(context.Background(), *pi)
			if err != nil {
				fmt.Println(err)
			}
		}

		connectedPeers := host.Network().Peers()
		fmt.Println("Connected peers:")
		for _, p := range connectedPeers {
			fmt.Println(p)
		}

		return host
	}
}
