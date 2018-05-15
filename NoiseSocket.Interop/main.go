package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/flynn/noise"
	"gopkg.in/noisesocket.v0"
)

func main() {
	priv, _ := base64.StdEncoding.DecodeString("vFilCT/FcyeShgbpTUrpru9n5yzZey8yfhsAx6DeL80=")
	pub, _ := base64.StdEncoding.DecodeString("J6TRfRXR5skWt6w5cFyaBxX8LPeIVxboZTLXTMhk4HM=")
	key := noise.DHKey{Private: priv, Public: pub}

	config := &noisesocket.ConnectionConfig{StaticKey: key}
	l, err := noisesocket.Listen(":10101", config)

	if err != nil {
		log.Fatal(err)
	}

	for {
		conn, err := l.Accept()

		if err != nil {
			log.Fatal(err)
		}

		go serve(conn)
	}
}

func serve(conn net.Conn) {
	buf := make([]byte, 1024)

	for {
		n, err := conn.Read(buf)

		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}

		fmt.Println(string(buf[:n]))

		if _, err = conn.Write(buf[:n]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
	}
}
