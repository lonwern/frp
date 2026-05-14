// Copyright 2017 fatedier, fatedier@gmail.com
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
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	libio "github.com/fatedier/golib/io"
	gosocks5 "github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	netpkg "github.com/fatedier/frp/pkg/util/net"
)

const socks5ConnectTimeout = 10 * time.Second

func init() {
	Register(v1.PluginSocks5, NewSocks5Plugin)
}

type Socks5Plugin struct {
	Server *gosocks5.Server
	dial   func(ctx context.Context, network, addr string) (net.Conn, error)
}

func NewSocks5Plugin(options v1.ClientPluginOptions) (Plugin, error) {
	opts := options.(*v1.Socks5PluginOptions)

	sp := &Socks5Plugin{
		dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: socks5ConnectTimeout}
			return dialer.DialContext(ctx, network, addr)
		},
	}
	serverOptions := []gosocks5.Option{
		gosocks5.WithLogger(gosocks5.NewLogger(log.New(io.Discard, "", log.LstdFlags))),
		gosocks5.WithResolver(socks5Resolver{}),
		gosocks5.WithConnectHandle(sp.handleConnect),
		gosocks5.WithAssociateHandle(socks5CommandNotSupported),
	}
	if opts.Username != "" || opts.Password != "" {
		serverOptions = append(serverOptions,
			gosocks5.WithCredential(gosocks5.StaticCredentials{opts.Username: opts.Password}),
		)
	}
	sp.Server = gosocks5.NewServer(serverOptions...)
	return sp, nil
}

func (sp *Socks5Plugin) Handle(conn io.ReadWriteCloser, realConn net.Conn, _ *ExtraInfo) {
	defer conn.Close()
	wrapConn := netpkg.WrapReadWriteCloserToConn(conn, realConn)
	_ = sp.Server.ServeConn(wrapConn)
}

func (sp *Socks5Plugin) Name() string {
	return v1.PluginSocks5
}

func (sp *Socks5Plugin) Close() error {
	return nil
}

func (sp *Socks5Plugin) handleConnect(ctx context.Context, writer io.Writer, request *gosocks5.Request) error {
	target, err := sp.dial(ctx, "tcp", request.DestAddr.String())
	if err != nil {
		if replyErr := gosocks5.SendReply(writer, socks5ReplyFromDialError(err), nil); replyErr != nil {
			return fmt.Errorf("failed to send reply: %w", replyErr)
		}
		return fmt.Errorf("connect to %v failed: %w", request.RawDestAddr, err)
	}

	if err := gosocks5.SendReply(writer, statute.RepSuccess, target.LocalAddr()); err != nil {
		target.Close()
		return fmt.Errorf("failed to send reply: %w", err)
	}

	client, ok := writer.(io.ReadWriteCloser)
	if !ok {
		target.Close()
		return fmt.Errorf("socks5 client connection does not implement io.ReadWriteCloser")
	}
	clientConn := libio.WrapReadWriteCloser(request.Reader, writer, client.Close)
	_, _, _ = libio.Join(target, clientConn)
	return nil
}

func socks5CommandNotSupported(_ context.Context, writer io.Writer, _ *gosocks5.Request) error {
	if err := gosocks5.SendReply(writer, statute.RepCommandNotSupported, nil); err != nil {
		return fmt.Errorf("failed to send reply: %w", err)
	}
	return nil
}

func socks5ReplyFromDialError(err error) uint8 {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "refused"):
		return statute.RepConnectionRefused
	case strings.Contains(msg, "network is unreachable"):
		return statute.RepNetworkUnreachable
	default:
		return statute.RepHostUnreachable
	}
}

type socks5Resolver struct{}

func (socks5Resolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	resolveCtx, cancel := context.WithTimeout(ctx, socks5ConnectTimeout)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupIPAddr(resolveCtx, name)
	if err != nil {
		return ctx, nil, err
	}
	if len(addrs) == 0 {
		return ctx, nil, fmt.Errorf("failed to resolve destination %q", name)
	}
	return ctx, addrs[0].IP, nil
}
