package main

import (
	"sync"
	"time"
	"yyakovliev-rgr/client"
	"yyakovliev-rgr/server"
)

func main() {
	var wg sync.WaitGroup
	wg.Add(2)

	go server.StartServer(&wg)
	time.Sleep(1 * time.Second)
	go client.StartClient(&wg)

	wg.Wait()
}
