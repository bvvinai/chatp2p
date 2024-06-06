package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func main() {

	http.HandleFunc("/inithost/", handleInitHost)
	http.HandleFunc("/connect/", handleConnectPeer)
	fmt.Println("Server listening on port 8080...")
	http.ListenAndServe(":8080", nil)
	// go connectToPeer("12D3KooWHeAvNK221WW7heHbrv6sgQf1FoPmucN2gbFTkCd2nt8T")
	// go connectToPeer("12D3KooWQFeTgsRRyRqeLGVNC76HTpvyJTZKvNSQEnBbxiLNqNGT")
}

func handleInitHost(w http.ResponseWriter, r *http.Request) {

	response := initHost("bvvinai", "bvvinai@1357")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleConnectPeer(w http.ResponseWriter, r *http.Request) {
	peerid := r.URL.Query().Get("peerid")
	response := connectToPeer(peerid)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
