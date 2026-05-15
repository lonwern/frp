package plugin

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/onsi/ginkgo/v2"

	"github.com/fatedier/frp/pkg/transport"
	"github.com/fatedier/frp/test/e2e/framework"
	"github.com/fatedier/frp/test/e2e/framework/consts"
	"github.com/fatedier/frp/test/e2e/mock/server/httpserver"
	"github.com/fatedier/frp/test/e2e/mock/server/streamserver"
	"github.com/fatedier/frp/test/e2e/pkg/cert"
	"github.com/fatedier/frp/test/e2e/pkg/port"
	"github.com/fatedier/frp/test/e2e/pkg/request"
	"github.com/fatedier/frp/test/e2e/pkg/rpc"
)

var _ = ginkgo.Describe("[Feature: Client-Plugins]", func() {
	f := framework.NewDefaultFramework()

	ginkgo.Describe("UnixDomainSocket", func() {
		ginkgo.It("Expose a unix domain socket echo server", func() {
			serverConf := consts.DefaultServerConfig
			var clientConf strings.Builder
			clientConf.WriteString(consts.DefaultClientConfig)

			getProxyConf := func(proxyName string, portName string, extra string) string {
				return fmt.Sprintf(`
				[[proxies]]
				name = "%s"
				type = "tcp"
				remotePort = {{ .%s }}
				`+extra, proxyName, portName) + fmt.Sprintf(`
				[proxies.plugin]
				type = "unix_domain_socket"
				unixPath = "{{ .%s }}"
				`, framework.UDSEchoServerAddr)
			}

			tests := []struct {
				proxyName   string
				portName    string
				extraConfig string
			}{
				{
					proxyName: "normal",
					portName:  port.GenName("Normal"),
				},
				{
					proxyName:   "with-encryption",
					portName:    port.GenName("WithEncryption"),
					extraConfig: "transport.useEncryption = true",
				},
				{
					proxyName:   "with-compression",
					portName:    port.GenName("WithCompression"),
					extraConfig: "transport.useCompression = true",
				},
				{
					proxyName: "with-encryption-and-compression",
					portName:  port.GenName("WithEncryptionAndCompression"),
					extraConfig: `
					transport.useEncryption = true
					transport.useCompression = true
					`,
				},
			}

			// build all client config
			for _, test := range tests {
				clientConf.WriteString(getProxyConf(test.proxyName, test.portName, test.extraConfig) + "\n")
			}
			// run frps and frpc
			f.RunProcesses(serverConf, []string{clientConf.String()})

			for _, test := range tests {
				framework.NewRequestExpect(f).Port(f.PortByName(test.portName)).Ensure()
			}
		})
	})

	ginkgo.It("http_proxy", func() {
		serverConf := consts.DefaultServerConfig
		clientConf := consts.DefaultClientConfig

		remotePort := f.AllocPort()
		clientConf += fmt.Sprintf(`
		[[proxies]]
		name = "tcp"
		type = "tcp"
		remotePort = %d
		[proxies.plugin]
		type = "http_proxy"
		httpUser = "abc"
		httpPassword = "123"
		`, remotePort)

		f.RunProcesses(serverConf, []string{clientConf})

		// http proxy, no auth info
		framework.NewRequestExpect(f).PortName(framework.HTTPSimpleServerPort).RequestModify(func(r *request.Request) {
			r.HTTP().Proxy("http://127.0.0.1:" + strconv.Itoa(remotePort))
		}).Ensure(framework.ExpectResponseCode(407))

		// http proxy, correct auth
		framework.NewRequestExpect(f).PortName(framework.HTTPSimpleServerPort).RequestModify(func(r *request.Request) {
			r.HTTP().Proxy("http://abc:123@127.0.0.1:" + strconv.Itoa(remotePort))
		}).Ensure()

		// connect TCP server by CONNECT method
		framework.NewRequestExpect(f).PortName(framework.TCPEchoServerPort).RequestModify(func(r *request.Request) {
			r.TCP().Proxy("http://abc:123@127.0.0.1:" + strconv.Itoa(remotePort))
		})
	})

	ginkgo.It("socks5 proxy", func() {
		serverConf := consts.DefaultServerConfig
		clientConf := consts.DefaultClientConfig

		remotePort := f.AllocPort()
		clientConf += fmt.Sprintf(`
		[[proxies]]
		name = "tcp"
		type = "tcp"
		remotePort = %d
		[proxies.plugin]
		type = "socks5"
		username = "abc"
		password = "123"
		`, remotePort)

		f.RunProcesses(serverConf, []string{clientConf})

		// http proxy, no auth info
		framework.NewRequestExpect(f).PortName(framework.TCPEchoServerPort).RequestModify(func(r *request.Request) {
			r.TCP().Proxy("socks5://127.0.0.1:" + strconv.Itoa(remotePort))
		}).ExpectError(true).Ensure()

		// http proxy, correct auth
		framework.NewRequestExpect(f).PortName(framework.TCPEchoServerPort).RequestModify(func(r *request.Request) {
			r.TCP().Proxy("socks5://abc:123@127.0.0.1:" + strconv.Itoa(remotePort))
		}).Ensure()
	})

	ginkgo.It("socks5 proxy handles concurrent tcp requests", func() {
		const concurrency = 64

		serverConf := consts.DefaultServerConfig + fmt.Sprintf(`
		transport.maxPoolCount = %d
		`, concurrency)
		clientConf := consts.DefaultClientConfig + fmt.Sprintf(`
		transport.poolCount = %d
		`, concurrency)

		remotePort := f.AllocPort()
		targetPort := f.AllocPort()
		clientConf += fmt.Sprintf(`
		[[proxies]]
		name = "tcp"
		type = "tcp"
		remotePort = %d
		[proxies.plugin]
		type = "socks5"
		username = "abc"
		password = "123"
		`, remotePort)

		// The barrier keeps all target connections open until every SOCKS5
		// CONNECT has completed, so this verifies true concurrent handling.
		readyCh := make(chan struct{})
		var readyOnce sync.Once
		var activeTargetConns atomic.Int32
		targetServer := streamserver.New(streamserver.TCP,
			streamserver.WithBindPort(targetPort),
			streamserver.WithCustomHandler(func(c net.Conn) {
				defer c.Close()
				if activeTargetConns.Add(1) == concurrency {
					readyOnce.Do(func() {
						close(readyCh)
					})
				}

				select {
				case <-readyCh:
				case <-time.After(10 * time.Second):
					return
				}

				buf, err := rpc.ReadBytes(c)
				if err != nil {
					return
				}
				_, _ = rpc.WriteBytes(c, buf)
			}),
		)
		f.RunServer("", targetServer)
		f.RunProcesses(serverConf, []string{clientConf})

		errCh := make(chan error, concurrency)
		var wg sync.WaitGroup
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()
				payload := []byte(fmt.Sprintf("%s-%d", consts.TestString, index))
				resp, err := request.New().
					TCP().
					Port(targetPort).
					Proxy("socks5://abc:123@127.0.0.1:" + strconv.Itoa(remotePort)).
					Timeout(10 * time.Second).
					Body(payload).
					Do()
				if err != nil {
					errCh <- fmt.Errorf("request %d failed: %w", index, err)
					return
				}
				if !bytes.Equal(resp.Content, payload) {
					errCh <- fmt.Errorf("request %d response = %q, want %q", index, resp.Content, payload)
					return
				}
			}(i)
		}
		wg.Wait()
		close(errCh)

		for err := range errCh {
			framework.ExpectNoError(err)
		}
	})

	ginkgo.It("socks5 proxy handles concurrent web console requests", func() {
		const resourceCount = 64

		serverConf := consts.DefaultServerConfig + fmt.Sprintf(`
		transport.maxPoolCount = %d
		`, resourceCount)
		clientConf := consts.DefaultClientConfig + fmt.Sprintf(`
		transport.poolCount = %d
		`, resourceCount)

		remotePort := f.AllocPort()
		webPort := f.AllocPort()
		clientConf += fmt.Sprintf(`
		[[proxies]]
		name = "tcp"
		type = "tcp"
		remotePort = %d
		[proxies.plugin]
		type = "socks5"
		username = "abc"
		password = "123"
		`, remotePort)

		readyCh := make(chan struct{})
		var readyOnce sync.Once
		var activeResourceRequests atomic.Int32
		webServer := httpserver.New(
			httpserver.WithBindPort(webPort),
			httpserver.WithHandler(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.URL.Path == "/" {
					var page strings.Builder
					page.WriteString("<!doctype html><title>console</title>")
					for i := 0; i < resourceCount; i++ {
						page.WriteString(fmt.Sprintf(`<script src="/assets/%d.js"></script>`, i))
					}
					_, _ = w.Write([]byte(page.String()))
					return
				}

				if strings.HasPrefix(req.URL.Path, "/assets/") {
					if activeResourceRequests.Add(1) == resourceCount {
						readyOnce.Do(func() {
							close(readyCh)
						})
					}

					select {
					case <-readyCh:
					case <-time.After(10 * time.Second):
						http.Error(w, "timeout waiting for concurrent requests", http.StatusGatewayTimeout)
						return
					}

					w.Header().Set("Content-Type", "application/javascript")
					_, _ = w.Write([]byte("window.__frp_console_asset_loaded = true;"))
					return
				}

				http.NotFound(w, req)
			})),
		)
		f.RunServer("", webServer)
		f.RunProcesses(serverConf, []string{clientConf})

		proxyURL, err := url.Parse("socks5://abc:123@127.0.0.1:" + strconv.Itoa(remotePort))
		framework.ExpectNoError(err)
		transport := &http.Transport{
			Proxy:                 http.ProxyURL(proxyURL),
			MaxIdleConns:          resourceCount + 1,
			MaxIdleConnsPerHost:   resourceCount + 1,
			ResponseHeaderTimeout: 10 * time.Second,
		}
		defer transport.CloseIdleConnections()
		httpClient := &http.Client{
			Transport: transport,
			Timeout:   15 * time.Second,
		}

		baseURL := "http://127.0.0.1:" + strconv.Itoa(webPort)
		indexBody, err := fetchHTTPBody(httpClient, baseURL+"/")
		framework.ExpectNoError(err)
		framework.ExpectTrue(bytes.Contains(indexBody, []byte("/assets/0.js")))

		errCh := make(chan error, resourceCount)
		var wg sync.WaitGroup
		for i := 0; i < resourceCount; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()
				body, err := fetchHTTPBody(httpClient, fmt.Sprintf("%s/assets/%d.js", baseURL, index))
				if err != nil {
					errCh <- fmt.Errorf("fetch asset %d: %w", index, err)
					return
				}
				if !bytes.Contains(body, []byte("__frp_console_asset_loaded")) {
					errCh <- fmt.Errorf("asset %d response = %q", index, body)
				}
			}(i)
		}
		wg.Wait()
		close(errCh)

		for err := range errCh {
			framework.ExpectNoError(err)
		}
	})

	ginkgo.It("static_file", func() {
		vhostPort := f.AllocPort()
		serverConf := consts.DefaultServerConfig + fmt.Sprintf(`
		vhostHTTPPort = %d
		`, vhostPort)
		clientConf := consts.DefaultClientConfig

		remotePort := f.AllocPort()
		f.WriteTempFile("test_static_file", "foo")
		clientConf += fmt.Sprintf(`
		[[proxies]]
		name = "tcp"
		type = "tcp"
		remotePort = %d
		[proxies.plugin]
		type = "static_file"
		localPath = "%s"

		[[proxies]]
		name = "http"
		type = "http"
		customDomains = ["example.com"]
		[proxies.plugin]
		type = "static_file"
		localPath = "%s"

		[[proxies]]
		name = "http-with-auth"
		type = "http"
		customDomains = ["other.example.com"]
		[proxies.plugin]
		type = "static_file"
		localPath = "%s"
		httpUser = "abc"
		httpPassword = "123"
		`, remotePort, f.TempDirectory, f.TempDirectory, f.TempDirectory)

		f.RunProcesses(serverConf, []string{clientConf})

		// from tcp proxy
		framework.NewRequestExpect(f).Request(
			framework.NewHTTPRequest().HTTPPath("/test_static_file").Port(remotePort),
		).ExpectResp([]byte("foo")).Ensure()

		// from http proxy without auth
		framework.NewRequestExpect(f).Request(
			framework.NewHTTPRequest().HTTPHost("example.com").HTTPPath("/test_static_file").Port(vhostPort),
		).ExpectResp([]byte("foo")).Ensure()

		// from http proxy with auth
		framework.NewRequestExpect(f).Request(
			framework.NewHTTPRequest().HTTPHost("other.example.com").HTTPPath("/test_static_file").Port(vhostPort).HTTPAuth("abc", "123"),
		).ExpectResp([]byte("foo")).Ensure()
	})

	ginkgo.It("http2https", func() {
		serverConf := consts.DefaultServerConfig
		vhostHTTPPort := f.AllocPort()
		serverConf += fmt.Sprintf(`
		vhostHTTPPort = %d
		`, vhostHTTPPort)

		localPort := f.AllocPort()
		clientConf := consts.DefaultClientConfig + fmt.Sprintf(`
		[[proxies]]
		name = "http2https"
		type = "http"
		customDomains = ["example.com"]
		[proxies.plugin]
		type = "http2https"
		localAddr = "127.0.0.1:%d"
		`, localPort)

		f.RunProcesses(serverConf, []string{clientConf})

		tlsConfig, err := transport.NewServerTLSConfig("", "", "")
		framework.ExpectNoError(err)
		localServer := httpserver.New(
			httpserver.WithBindPort(localPort),
			httpserver.WithTLSConfig(tlsConfig),
			httpserver.WithResponse([]byte("test")),
		)
		f.RunServer("", localServer)

		framework.NewRequestExpect(f).
			Port(vhostHTTPPort).
			RequestModify(func(r *request.Request) {
				r.HTTP().HTTPHost("example.com")
			}).
			ExpectResp([]byte("test")).
			Ensure()
	})

	ginkgo.It("https2http", func() {
		generator := &cert.SelfSignedCertGenerator{}
		artifacts, err := generator.Generate("example.com")
		framework.ExpectNoError(err)
		crtPath := f.WriteTempFile("server.crt", string(artifacts.Cert))
		keyPath := f.WriteTempFile("server.key", string(artifacts.Key))

		serverConf := consts.DefaultServerConfig
		vhostHTTPSPort := f.AllocPort()
		serverConf += fmt.Sprintf(`
		vhostHTTPSPort = %d
		`, vhostHTTPSPort)

		localPort := f.AllocPort()
		clientConf := consts.DefaultClientConfig + fmt.Sprintf(`
		[[proxies]]
		name = "https2http"
		type = "https"
		customDomains = ["example.com"]
		[proxies.plugin]
		type = "https2http"
		localAddr = "127.0.0.1:%d"
		crtPath = "%s"
		keyPath = "%s"
		`, localPort, crtPath, keyPath)

		f.RunProcesses(serverConf, []string{clientConf})

		localServer := httpserver.New(
			httpserver.WithBindPort(localPort),
			httpserver.WithResponse([]byte("test")),
		)
		f.RunServer("", localServer)

		framework.NewRequestExpect(f).
			Port(vhostHTTPSPort).
			RequestModify(func(r *request.Request) {
				r.HTTPS().HTTPHost("example.com").TLSConfig(&tls.Config{
					ServerName:         "example.com",
					InsecureSkipVerify: true,
				})
			}).
			ExpectResp([]byte("test")).
			Ensure()
	})

	ginkgo.It("https2https", func() {
		generator := &cert.SelfSignedCertGenerator{}
		artifacts, err := generator.Generate("example.com")
		framework.ExpectNoError(err)
		crtPath := f.WriteTempFile("server.crt", string(artifacts.Cert))
		keyPath := f.WriteTempFile("server.key", string(artifacts.Key))

		serverConf := consts.DefaultServerConfig
		vhostHTTPSPort := f.AllocPort()
		serverConf += fmt.Sprintf(`
		vhostHTTPSPort = %d
		`, vhostHTTPSPort)

		localPort := f.AllocPort()
		clientConf := consts.DefaultClientConfig + fmt.Sprintf(`
		[[proxies]]
		name = "https2https"
		type = "https"
		customDomains = ["example.com"]
		[proxies.plugin]
		type = "https2https"
		localAddr = "127.0.0.1:%d"
		crtPath = "%s"
		keyPath = "%s"
		`, localPort, crtPath, keyPath)

		f.RunProcesses(serverConf, []string{clientConf})

		tlsConfig, err := transport.NewServerTLSConfig("", "", "")
		framework.ExpectNoError(err)
		localServer := httpserver.New(
			httpserver.WithBindPort(localPort),
			httpserver.WithResponse([]byte("test")),
			httpserver.WithTLSConfig(tlsConfig),
		)
		f.RunServer("", localServer)

		framework.NewRequestExpect(f).
			Port(vhostHTTPSPort).
			RequestModify(func(r *request.Request) {
				r.HTTPS().HTTPHost("example.com").TLSConfig(&tls.Config{
					ServerName:         "example.com",
					InsecureSkipVerify: true,
				})
			}).
			ExpectResp([]byte("test")).
			Ensure()
	})

	ginkgo.Describe("http2http", func() {
		ginkgo.It("host header rewrite", func() {
			serverConf := consts.DefaultServerConfig

			localPort := f.AllocPort()
			remotePort := f.AllocPort()
			clientConf := consts.DefaultClientConfig + fmt.Sprintf(`
			[[proxies]]
			name = "http2http"
			type = "tcp"
			remotePort = %d
			[proxies.plugin]
			type = "http2http"
			localAddr = "127.0.0.1:%d"
			hostHeaderRewrite = "rewrite.test.com"
			`, remotePort, localPort)

			f.RunProcesses(serverConf, []string{clientConf})

			localServer := httpserver.New(
				httpserver.WithBindPort(localPort),
				httpserver.WithHandler(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					_, _ = w.Write([]byte(req.Host))
				})),
			)
			f.RunServer("", localServer)

			framework.NewRequestExpect(f).
				Port(remotePort).
				RequestModify(func(r *request.Request) {
					r.HTTP().HTTPHost("example.com")
				}).
				ExpectResp([]byte("rewrite.test.com")).
				Ensure()
		})

		ginkgo.It("set request header", func() {
			serverConf := consts.DefaultServerConfig

			localPort := f.AllocPort()
			remotePort := f.AllocPort()
			clientConf := consts.DefaultClientConfig + fmt.Sprintf(`
			[[proxies]]
			name = "http2http"
			type = "tcp"
			remotePort = %d
			[proxies.plugin]
			type = "http2http"
			localAddr = "127.0.0.1:%d"
			requestHeaders.set.x-from-where = "frp"
			`, remotePort, localPort)

			f.RunProcesses(serverConf, []string{clientConf})

			localServer := httpserver.New(
				httpserver.WithBindPort(localPort),
				httpserver.WithHandler(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					_, _ = w.Write([]byte(req.Header.Get("x-from-where")))
				})),
			)
			f.RunServer("", localServer)

			framework.NewRequestExpect(f).
				Port(remotePort).
				RequestModify(func(r *request.Request) {
					r.HTTP().HTTPHost("example.com")
				}).
				ExpectResp([]byte("frp")).
				Ensure()
		})
	})

	ginkgo.It("tls2raw", func() {
		generator := &cert.SelfSignedCertGenerator{}
		artifacts, err := generator.Generate("example.com")
		framework.ExpectNoError(err)
		crtPath := f.WriteTempFile("tls2raw_server.crt", string(artifacts.Cert))
		keyPath := f.WriteTempFile("tls2raw_server.key", string(artifacts.Key))

		serverConf := consts.DefaultServerConfig
		vhostHTTPSPort := f.AllocPort()
		serverConf += fmt.Sprintf(`
		vhostHTTPSPort = %d
		`, vhostHTTPSPort)

		localPort := f.AllocPort()
		clientConf := consts.DefaultClientConfig + fmt.Sprintf(`
		[[proxies]]
		name = "tls2raw-test"
		type = "https"
		customDomains = ["example.com"]
		[proxies.plugin]
		type = "tls2raw"
		localAddr = "127.0.0.1:%d"
		crtPath = "%s"
		keyPath = "%s"
		`, localPort, crtPath, keyPath)

		f.RunProcesses(serverConf, []string{clientConf})

		localServer := httpserver.New(
			httpserver.WithBindPort(localPort),
			httpserver.WithResponse([]byte("test")),
		)
		f.RunServer("", localServer)

		framework.NewRequestExpect(f).
			Port(vhostHTTPSPort).
			RequestModify(func(r *request.Request) {
				r.HTTPS().HTTPHost("example.com").TLSConfig(&tls.Config{
					ServerName:         "example.com",
					InsecureSkipVerify: true,
				})
			}).
			ExpectResp([]byte("test")).
			Ensure()
	})
})

func fetchHTTPBody(client *http.Client, targetURL string) ([]byte, error) {
	resp, err := client.Get(targetURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s returned status %d with body %q", targetURL, resp.StatusCode, body)
	}
	return body, nil
}
