package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"example.com/customer-crypto-grpc-v2/core"
	"example.com/customer-crypto-grpc-v2/service"
	"example.com/customer-crypto-grpc-v2/storage"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

type Identity struct {
	ID     string `json:"id"`
	Token  string `json:"token"`
	Secret []byte `json:"secret"`
}

func main() {
	db := flag.String("db", "demo.db", "database")
	dir := flag.String("identities", "identities", "client credential directory")
	flag.Parse()
	s, e := storage.Open(*db)
	if e != nil {
		log.Fatal(e)
	}
	defer s.DB.Close()
	if e = os.MkdirAll(*dir, 0700); e != nil {
		log.Fatal(e)
	}
	roles := map[string]string{"customer1": "customer", "customer2": "customer", "customer3": "customer", "backoffice1": "backoffice", "backoffice2": "backoffice", "rotation": "rotation"}
	for _, id := range []string{"customer1", "customer2", "customer3", "backoffice1", "backoffice2", "rotation"} {
		server, e := core.NewClient("server-" + id)
		if e != nil {
			log.Fatal(e)
		}
		client, e := core.NewClient(id)
		if e != nil {
			log.Fatal(e)
		}
		t := make([]byte, 32)
		if _, e = rand.Read(t); e != nil {
			log.Fatal(e)
		}
		token := hex.EncodeToString(t)
		if e = s.Exec(`INSERT INTO principals(id,role,token,server_secret,server_public,client_public) VALUES(?,?,?,?,?,?)`, id, roles[id], token, server.Secret.FillBytes(make([]byte, 32)), service.EncodePoint(server.Public), service.EncodePoint(client.Public)); e != nil {
			log.Fatal("bootstrap requires empty database: ", e)
		}
		b, _ := json.MarshalIndent(Identity{id, token, client.Secret.FillBytes(make([]byte, 32))}, "", "  ")
		if e = os.WriteFile(filepath.Join(*dir, id+".json"), b, 0600); e != nil {
			log.Fatal(e)
		}
	}
	for _, pair := range [][2]string{{"customer1", "C001"}, {"customer2", "C002"}, {"customer3", "C003"}, {"backoffice1", "C001"}, {"backoffice1", "C002"}, {"backoffice2", "C002"}, {"backoffice2", "C003"}, {"rotation", "C001"}, {"rotation", "C002"}, {"rotation", "C003"}} {
		if e = s.Exec(`INSERT INTO grants(principal_id,object_id) VALUES(?,?)`, pair[0], pair[1]); e != nil {
			log.Fatal(e)
		}
	}
	for _, pair := range [][2]string{{"customer1", "C001"}, {"customer2", "C002"}, {"customer3", "C003"}} {
		if e = s.Exec(`INSERT INTO object_owners(principal_id,object_id) VALUES(?,?)`, pair[0], pair[1]); e != nil {
			log.Fatal(e)
		}
	}
	fmt.Println("Provisioned SQLite principals and six separate identity files. Bootstrap process must be trusted and deleted after provisioning.")
}
