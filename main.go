package main

import (
	"flag"
	"fmt"
	"net"
	"sync"
	"time"
)

var (
	portsChan     chan int
	resultTCPChan chan int
	resultUDPChan chan int
	hostname      *string
	wg            sync.WaitGroup
)

func worker() {
	defer wg.Done()
	for port := range portsChan {
		host := fmt.Sprintf("%s:%d", *hostname, port)

		//wg.Add(2)
		//go func() {
		fmt.Printf("checking tcp: %s\n", host)
		conn, err := net.DialTimeout("tcp", host, time.Second*1)
		if err == nil {
			resultTCPChan <- port
			conn.Close()
		}
		//	wg.Done()
		//}()

		//go func() {
		fmt.Printf("checking upd: %s\n", host)
		conn, err = net.DialTimeout("udp", host, time.Second*1)
		if err == nil {
			resultUDPChan <- port
			conn.Close()
		}
		//	wg.Done()
		//}()
	}
}

func main() {
	portsChan = make(chan int, 100)
	resultTCPChan = make(chan int, 100)
	resultUDPChan = make(chan int, 100)

	hostname = flag.String("host", "localhost", "Hostname or IP address")
	flag.Parse()

	numWorkers := 10000 // runtime.NumCPU() * 4
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker()
	}

	go func() {
		for i := 1; i <= 65535; i++ {
			portsChan <- i
		}
		close(portsChan)
	}()

	done := make(chan bool)

	go func() {
		var openTCPPorts []int
		for port := range resultTCPChan {
			openTCPPorts = append(openTCPPorts, port)
		}
		fmt.Printf("\nTCP: %v\n", openTCPPorts)
		var openUDPPorts []int
		for port := range resultUDPChan {
			openUDPPorts = append(openUDPPorts, port)
		}
		fmt.Printf("\nUDP: %v\n", openUDPPorts)
		done <- true
	}()

	wg.Wait()

	close(resultTCPChan)
	close(resultUDPChan)
	<-done
}
