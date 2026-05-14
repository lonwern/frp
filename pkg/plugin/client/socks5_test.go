// Copyright 2026 The frp Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !frps

package plugin

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	v1 "github.com/fatedier/frp/pkg/config/v1"
)

func TestSocks5PluginConcurrentAuthenticatedConnect(t *testing.T) {
	targetLn := startSocks5EchoServer(t)
	p, err := NewSocks5Plugin(&v1.Socks5PluginOptions{
		Username: "abc",
		Password: "123",
	})
	if err != nil {
		t.Fatalf("create socks5 plugin: %v", err)
	}
	t.Cleanup(func() {
		_ = p.Close()
	})
	sp := p.(*Socks5Plugin)

	const concurrency = 64
	errCh := make(chan error, concurrency)
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			errCh <- socks5RoundTripThroughPlugin(sp, targetLn.Addr().String(), index)
		}(i)
	}
	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func startSocks5EchoServer(t *testing.T) net.Listener {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target server: %v", err)
	}
	t.Cleanup(func() {
		_ = ln.Close()
	})

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return ln
}

func socks5RoundTripThroughPlugin(sp *Socks5Plugin, targetAddr string, index int) error {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		sp.Handle(serverConn, serverConn, nil)
	}()

	if err := clientConn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		serverConn.Close()
		return fmt.Errorf("client %d set deadline: %w", index, err)
	}
	defer clientConn.SetDeadline(time.Time{})

	if err := socks5Connect(clientConn, targetAddr, "abc", "123"); err != nil {
		serverConn.Close()
		return fmt.Errorf("client %d connect through socks5: %w", index, err)
	}

	payload := []byte(fmt.Sprintf("hello-%d", index))
	if _, err := clientConn.Write(payload); err != nil {
		serverConn.Close()
		return fmt.Errorf("client %d write payload: %w", index, err)
	}

	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(clientConn, buf); err != nil {
		serverConn.Close()
		return fmt.Errorf("client %d read payload: %w", index, err)
	}
	if string(buf) != string(payload) {
		serverConn.Close()
		return fmt.Errorf("client %d payload = %q, want %q", index, buf, payload)
	}

	clientConn.Close()
	select {
	case <-doneCh:
	case <-time.After(3 * time.Second):
		serverConn.Close()
		return fmt.Errorf("client %d socks5 handler did not exit", index)
	}
	return nil
}

func socks5Connect(conn net.Conn, targetAddr, username, password string) error {
	if username == "" && password == "" {
		if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			return fmt.Errorf("write greeting: %w", err)
		}
	} else {
		if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
			return fmt.Errorf("write greeting: %w", err)
		}
	}

	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("read greeting reply: %w", err)
	}
	if reply[0] != 0x05 {
		return fmt.Errorf("unexpected greeting version: %v", reply)
	}
	if username != "" || password != "" {
		if reply[1] != 0x02 {
			return fmt.Errorf("unexpected auth method: %v", reply)
		}
		if err := socks5Authenticate(conn, username, password); err != nil {
			return err
		}
	} else if reply[1] != 0x00 {
		return fmt.Errorf("unexpected auth method: %v", reply)
	}

	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		return fmt.Errorf("target address %q is not an IPv4 address", targetAddr)
	}

	req := []byte{0x05, 0x01, 0x00, 0x01, ip[0], ip[1], ip[2], ip[3], byte(port >> 8), byte(port)}
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("write connect request: %w", err)
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("read connect reply header: %w", err)
	}
	if header[0] != 0x05 || header[1] != 0x00 {
		return fmt.Errorf("unexpected connect reply header: %v", header)
	}

	addrLen := 0
	switch header[3] {
	case 0x01:
		addrLen = net.IPv4len
	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return fmt.Errorf("read connect reply domain length: %w", err)
		}
		addrLen = int(lenBuf[0])
	case 0x04:
		addrLen = net.IPv6len
	default:
		return fmt.Errorf("unexpected connect reply address type: %d", header[3])
	}

	if _, err := io.CopyN(io.Discard, conn, int64(addrLen+2)); err != nil {
		return fmt.Errorf("read connect reply address: %w", err)
	}
	return nil
}

func socks5Authenticate(conn net.Conn, username, password string) error {
	if len(username) > 255 || len(password) > 255 {
		return fmt.Errorf("username or password is too long")
	}

	req := []byte{0x01, byte(len(username))}
	req = append(req, username...)
	req = append(req, byte(len(password)))
	req = append(req, password...)
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("write auth request: %w", err)
	}

	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("read auth reply: %w", err)
	}
	if reply[0] != 0x01 || reply[1] != 0x00 {
		return fmt.Errorf("unexpected auth reply: %v", reply)
	}
	return nil
}
