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
	verbosity int
)

func logInfo(format string, args ...interface{}) {
	if verbosity >= 1 {
		fmt.Printf("[INFO] "+format, args...)
	}
}

func logDebug(format string, args ...interface{}) {
	if verbosity >= 2 {
		fmt.Printf("[DEBUG] "+format, args...)
	}
}

func logTrace(format string, args ...interface{}) {
	if verbosity >= 3 {
		fmt.Printf("[TRACE] "+format, args...)
	}
}

func worker() {
	defer wg.Done()
	for port := range portsChan {
		host := fmt.Sprintf("%s:%d", *hostname, port)

		logTrace("Checking port %d...\n", port)

		startTime := time.Now()
		d := net.Dialer{Timeout: time.Second}
		conn, err := d.Dial("tcp", host)

		if err == nil {
			fmt.Printf("TCP: %d\n", port)
			logDebug("Connection established to port %d in %v\n",
				port, time.Since(startTime))
			conn.Close()
		} else {
			logTrace("Port %d is closed (%v)\n", port, err)
		}
	}
}

func main() {
	hostname = flag.String("host", "localhost", "Hostname or IP address")
	numWorkers := flag.Int("workers", 10000, "Number of concurrent workers")
	startPort := flag.Int("start", 1, "Start port")
	endPort := flag.Int("end", 65535, "End port")

	v := flag.Bool("v", false, "Enable verbose output (info)")
	vv := flag.Bool("vv", false, "Enable more verbose output (debug)")
	vvv := flag.Bool("vvv", false, "Enable most verbose output (trace)")

	flag.Parse()

	if *vvv {
		verbosity = 3
	} else if *vv {
		verbosity = 2
	} else if *v {
		verbosity = 1
	}

	startTime := time.Now()
	logInfo("Starting scan of %s (ports %d-%d) with %d workers\n",
		*hostname, *startPort, *endPort, *numWorkers)

	portCount := *endPort - *startPort + 1
	if *numWorkers > portCount {
		*numWorkers = portCount
		logDebug("Adjusted workers count to %d\n", *numWorkers)
	}

	portsChan = make(chan int, *numWorkers)

	logDebug("Starting %d workers...\n", *numWorkers)
	for i := 0; i < *numWorkers; i++ {
		wg.Add(1)
		go worker()
	}

	go func() {
		logDebug("Sending ports to channel...\n")
		for i := *startPort; i <= *endPort; i++ {
			portsChan <- i
		}
		logDebug("Finished sending ports, closing channel\n")
		close(portsChan)
	}()

	wg.Wait()
	duration := time.Since(startTime)
	logInfo("Scan completed in %v\n", duration)
}
