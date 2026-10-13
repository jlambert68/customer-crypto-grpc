package main

import (
	"example.com/customer-crypto-grpc-v2/protocol"
	"example.com/customer-crypto-grpc-v2/service"
	"example.com/customer-crypto-grpc-v2/storage"
	"flag"
	"google.golang.org/grpc"
	"log"
	"net"
)

func main() {
	db := flag.String("db", "demo.db", "SQLite path")
	addr := flag.String("listen", "127.0.0.1:50051", "listen address (localhost only)")
	flag.Parse()
	s, e := storage.Open(*db)
	if e != nil {
		log.Fatal(e)
	}
	defer s.DB.Close()
	l, e := net.Listen("tcp", *addr)
	if e != nil {
		log.Fatal(e)
	}
	g := grpc.NewServer(grpc.ForceServerCodec(protocol.JSONCodec{}))
	protocol.Register(g, &service.Service{Store: s})
	log.Printf("server listening on %s", *addr)
	log.Fatal(g.Serve(l))
}
