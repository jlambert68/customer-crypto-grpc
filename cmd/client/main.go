package main

import (
	"example.com/customer-crypto-grpc-v2/agent"
	"flag"
	"fmt"
	"log"
	"strings"
)

func main() {
	identity := flag.String("identity", "identities/customer1.json", "client identity file")
	addr := flag.String("server", "127.0.0.1:50051", "server")
	obj := flag.String("object", "C001", "customer object")
	v := flag.Uint64("version", 0, "version (0=latest)")
	set := flag.String("set", "", "replace one string field as name=value (record owner only)")
	flag.Parse()
	if *set != "" && *v != 0 {
		log.Fatal("updates must use the latest version; omit -version")
	}
	a, e := agent.Connect(*identity, *addr)
	if e != nil {
		log.Fatal(e)
	}
	defer a.Close()
	if *set != "" {
		field, value, ok := strings.Cut(*set, "=")
		field = strings.TrimSpace(field)
		if !ok || field == "" {
			log.Fatal("-set must use name=value")
		}
		next, updated, e := a.UpdateFields(*obj, map[string]string{field: value})
		if e != nil {
			log.Fatal(e)
		}
		fmt.Printf("%s updated %s to v%d with a fresh DEK: %s\n", a.ID.ID, *obj, next, string(updated))
		return
	}
	o, plain, e := a.Read(*obj, *v)
	if e != nil {
		log.Fatal(e)
	}
	fmt.Printf("%s read %s v%d: %s\n", a.ID.ID, o.ID, o.Version, string(plain))
}
