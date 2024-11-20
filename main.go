package main

import (
	"flag"
	"fmt"
	"net"
	"sync"
	"time"
)

var (
	portsChan chan int
	hostname  *string
	wg        sync.WaitGroup
)

func worker() {
	defer wg.Done()
	for port := range portsChan {
		host := fmt.Sprintf("%s:%d", *hostname, port)

		d := net.Dialer{Timeout: time.Second}
		conn, err := d.Dial("tcp", host)
		if err == nil {
			fmt.Printf("TCP: %d\n", port)
			conn.Close()
		}
	}
}

func main() {
	portsChan = make(chan int, 100)

	hostname = flag.String("host", "localhost", "Hostname or IP address")
	numWorkers := flag.Int("workers", 10000, "Number of concurrent workers")
	startPort := flag.Int("start", 1, "Start port")
	endPort := flag.Int("end", 65535, "End port")
	flag.Parse()

	portCount := *endPort - *startPort + 1
	if *numWorkers > portCount {
		*numWorkers = portCount
	}

	for i := 0; i < *numWorkers; i++ {
		wg.Add(1)
		go worker()
	}

	go func() {
		for i := *startPort; i <= *endPort; i++ {
			portsChan <- i
		}
		close(portsChan)
	}()

	wg.Wait()
}
