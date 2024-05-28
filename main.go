package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	badger "github.com/dgraph-io/badger/v4"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"golang.org/x/crypto/bcrypt"
)

//const chatProtocolID = "/chat/1.0.0"

func main() {

	hostID, err := getUserDetails()
	if err != nil || hostID == "" {
		fmt.Println(err)
		initHost("vinai", "bvvinai")
	} else {
		fmt.Printf("PeerID: %s\n", hostID)
	}

	//initHost("bvvinai", "bvvinai@1357")

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	fmt.Println("Received signal, shutting down...")
}

func getUserDetails() (peer.ID, error) {
	db, err := badger.Open(badger.DefaultOptions("./badger"))
	if err != nil {
		panic(err)
	}
	defer db.Close()

	var peerID string
	get_err := db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte("peerid"))
		if err != nil {
			return err
		}
		err = item.Value(func(val []byte) error {
			peerID = string(val)
			return nil
		})
		return err
	})
	return peer.ID(peerID), get_err
}

func initHost(username, password string) {

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

	host, err := libp2p.New(libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"), libp2p.Identity(priv))
	if err != nil {
		panic(err)
	}
	defer host.Close()
	fmt.Println(hashedPassword)
	fmt.Println(priv)
	fmt.Println(host.ID())

	db, err := badger.Open(badger.DefaultOptions("./badger"))
	if err != nil {
		panic(err)
	}
	defer db.Close()

	txn := db.NewTransaction(true)
	defer txn.Discard()

	txn.Set([]byte("username"), []byte(username))
	txn.Set([]byte("password"), hashedPassword)
	txn.Set([]byte("priv"), privBytes)
	txn.Set([]byte("peerid"), []byte(host.ID()))
	txn.Commit()
}
