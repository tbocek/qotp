package main

import (
	"os"
	"fmt"
	"log"

	"github.com/tbocek/qotp"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage:")
		fmt.Println("  go run example1.go server [addr]     # default: 127.0.0.1:8888")
		fmt.Println("  go run example1.go client [addr]     # default: 127.0.0.1:8888")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "server":
		addr := "127.0.0.1:8888"
		if len(os.Args) > 2 {
			addr = os.Args[2]
		}
		runServer(addr)
	case "client":
		addr := "127.0.0.1:8888"
		if len(os.Args) > 2 {
			addr = os.Args[2]
		}
		runClient(addr)
	default:
		fmt.Println("First argument must be 'server' or 'client'")
		os.Exit(1)
	}
}

func runServer(addr string) {
	// Create server listener (will auto-generate keys)
	listener, err := qotp.Listen(qotp.WithListenAddr(addr))
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	fmt.Printf("Server listening on %s\n", addr)
	fmt.Println("Waiting for clients...")

	// Handle incoming streams
	listener.Loop(func(stream *qotp.Stream) bool {
		if stream == nil { //nothing to read
			return true
		}
		data, err := stream.Read()
		if err != nil {
			return false
		}
		
		if len(data) > 0 {
			fmt.Printf("Server received: %s\n", data)
			
			// Send reply
			stream.Write([]byte("Hello from server!"))
			stream.Close()
		}
		return true
	})
}

func runClient(serverAddr string) {
	// Create client listener (will auto-generate keys)
	listener, err := qotp.Listen()
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	// Connect to server without crypto (in-band key exchange)
	conn, err := listener.DialString(serverAddr)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Connected to server at %s\n", serverAddr)

	// Send message
	stream := conn.Stream(0)
	_, err = stream.Write([]byte("Hello from client!"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Sent: Hello from client!")

	// Read reply
	listener.Loop(func(s *qotp.Stream) bool {
		if s == nil { //nothing to read
			return true //continue
		}
		data, _ := s.Read()
		if len(data) > 0 {
			fmt.Printf("Received: %s\n", data)
			return false //exit
		}
		return true //continue
	})
}