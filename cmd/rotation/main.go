package main

import (
	"example.com/customer-crypto-grpc-v2/agent"
	"example.com/customer-crypto-grpc-v2/service"
	"flag"
	"fmt"
	"log"
)

func main() {
	identity := flag.String("identity", "identities/rotation.json", "rotation credentials")
	addr := flag.String("server", "127.0.0.1:50051", "server")
	action := flag.String("action", "jobs", "seed, revoke, jobs, rotate")
	target := flag.String("target", "backoffice1", "principal to revoke")
	flag.Parse()
	a, e := agent.Connect(*identity, *addr)
	if e != nil {
		log.Fatal(e)
	}
	defer a.Close()
	switch *action {
	case "seed":
		samples := map[string]string{
			"C001": `{"customer_id":"C001","name":"Anna Andersson","email":"anna@example.test","phone":"070-1111111","city":"Stockholm","notes":"Customer since 2024"}`,
			"C002": `{"customer_id":"C002","name":"Bertil Berg","email":"bertil@example.test","phone":"070-2222222","city":"Uppsala","notes":"Premium customer"}`,
			"C003": `{"customer_id":"C003","name":"Cecilia Carlsson","email":"cecilia@example.test","phone":"070-3333333","city":"Nacka","notes":"Prefers email"}`}
		for _, id := range []string{"C001", "C002", "C003"} {
			if e = a.EncryptAndUpload(id, 1, []byte(samples[id])); e != nil {
				log.Fatal(e)
			}
			fmt.Println("seeded", id)
		}
	case "revoke":
		var r service.Empty
		if e = a.Call("revoke", service.RevokeArgs{ID: *target}, &r); e != nil {
			log.Fatal(e)
		}
		fmt.Println("revoked", *target)
	case "jobs":
		var jobs []service.Job
		if e = a.Call("jobs", service.Empty{}, &jobs); e != nil {
			log.Fatal(e)
		}
		fmt.Printf("pending jobs: %+v\n", jobs)
	case "rotate":
		var jobs []service.Job
		if e = a.Call("jobs", service.Empty{}, &jobs); e != nil {
			log.Fatal(e)
		}
		for _, job := range jobs {
			if e = a.Rotate(job.ID, job.Next); e != nil {
				log.Fatal(e)
			}
		}
	default:
		log.Fatal("unknown action")
	}
}
