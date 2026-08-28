package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"sort"
	"strconv"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"

	"github.com/0typos/mimic/internal/config"
	"github.com/0typos/mimic/internal/profiles"
)

func (s *Server) handleHTTP(ctx context.Context, conn net.Conn, definition config.Listener) error {
	reader := bufio.NewReader(conn)
	request, err := http.ReadRequest(reader)
	if err != nil {
		return err
	}
	if request.Method == http.MethodConnect {
		request.Body.Close()
		if definition.Mode == "intercept" {
			return s.interceptConnect(ctx, conn, reader, request.Host)
		}
		return s.tunnelConnect(ctx, conn, reader, request.Host)
	}
	return s.serveHTTP(ctx, conn, reader, request, "", false)
}

func (s *Server) tunnelConnect(ctx context.Context, client net.Conn, buffered *bufio.Reader, target string) error {
	target = withDefaultPort(target, "443")
	snapshot := s.state.Snapshot()
	upstream, err := net.DialTimeout("tcp", target, duration(snapshot.Config.Runtime.ConnectTimeout))
	if err != nil {
		writeProxyError(client, http.StatusBadGateway, err)
		return err
	}
	defer upstream.Close()
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\nProxy-Agent: mimic\r\n\r\n"); err != nil {
		return err
	}
	return tunnel(ctx, &bufferedConn{Conn: client, reader: buffered}, upstream)
}

func (s *Server) interceptConnect(ctx context.Context, client net.Conn, buffered *bufio.Reader, target string) error {
	if s.authority == nil {
		return errors.New("interception requested without a loaded CA")
	}
	target = withDefaultPort(target, "443")
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\nProxy-Agent: mimic\r\n\r\n"); err != nil {
		return err
	}
	serverConfig, err := s.authority.TLSConfig(host)
	if err != nil {
		return err
	}
	tlsClient := tls.Server(&bufferedConn{Conn: client, reader: buffered}, serverConfig)
	if err := tlsClient.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("downstream TLS handshake: %w", err)
	}
	defer tlsClient.Close()
	reader := bufio.NewReader(tlsClient)
	request, err := http.ReadRequest(reader)
	if err != nil {
		return err
	}
	return s.serveHTTP(ctx, tlsClient, reader, request, target, true)
}

func (s *Server) serveHTTP(ctx context.Context, client net.Conn, reader *bufio.Reader, first *http.Request, fixedTarget string, forceTLS bool) error {
	request := first
	for {
		if err := s.forwardHTTP(ctx, client, request, fixedTarget, forceTLS, ""); err != nil {
			writeProxyError(client, http.StatusBadGateway, err)
			return err
		}
		if request.Close {
			return nil
		}
		next, err := http.ReadRequest(reader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		request = next
	}
}

func (s *Server) forwardHTTP(ctx context.Context, client net.Conn, request *http.Request, fixedTarget string, forceTLS bool, forcedProfile string) error {
	if request.Body != nil {
		defer request.Body.Close()
	}
	target, useTLS, err := requestTarget(request, fixedTarget, forceTLS)
	if err != nil {
		return err
	}
	profileName := forcedProfile
	if headerProfile := request.Header.Get("X-Mimic-Profile"); headerProfile != "" {
		profileName = headerProfile
		request.Header.Del("X-Mimic-Profile")
	}
	var upstream net.Conn
	var profile profiles.Profile
	if useTLS {
		upstream, profile, err = s.dialer.DialProfile(ctx, target, profileName)
	} else {
		var ok bool
		profile, _, ok = s.state.ProfileForHostAs(target, profileName)
		if !ok {
			return fmt.Errorf("unknown profile %q", profileName)
		}
		snapshot := s.state.Snapshot()
		upstream, err = net.DialTimeout("tcp", target, duration(snapshot.Config.Runtime.ConnectTimeout))
	}
	if err != nil {
		return err
	}
	defer upstream.Close()
	s.state.RequestHandled()
	var response *http.Response
	if useTLS && negotiatedProtocol(upstream) == "h2" {
		response, err = roundTripH2(upstream, request, target, profile)
	} else {
		if err := writeProfiledRequest(upstream, request, profile); err != nil {
			return err
		}
		response, err = http.ReadResponse(bufio.NewReader(upstream), request)
		if err != nil {
			return fmt.Errorf("read upstream response: %w", err)
		}
	}
	defer response.Body.Close()
	removeHopHeaders(response.Header)
	response.Header.Set("Via", "1.1 mimic")
	response.Close = request.Close
	if err := response.Write(client); err != nil {
		return fmt.Errorf("write downstream response: %w", err)
	}
	return nil
}

func requestTarget(request *http.Request, fixed string, forceTLS bool) (string, bool, error) {
	if fixed != "" {
		return fixed, forceTLS, nil
	}
	host := request.URL.Host
	if host == "" {
		host = request.Host
	}
	if host == "" {
		return "", false, errors.New("request has no target host")
	}
	scheme := strings.ToLower(request.URL.Scheme)
	if scheme != "" && scheme != "http" && scheme != "https" {
		return "", false, fmt.Errorf("unsupported request URL scheme %q", request.URL.Scheme)
	}
	useTLS := scheme == "https"
	port := "80"
	if useTLS {
		port = "443"
	}
	return withDefaultPort(host, port), useTLS, nil
}

func writeProfiledRequest(writer io.Writer, request *http.Request, profile profiles.Profile) error {
	path := request.URL.RequestURI()
	if path == "" {
		path = request.RequestURI
	}
	if path == "" {
		path = "/"
	}
	if _, err := fmt.Fprintf(writer, "%s %s HTTP/1.1\r\n", request.Method, path); err != nil {
		return err
	}
	headers := request.Header.Clone()
	removeHopHeaders(headers)
	if profile.UserAgent != "" {
		headers.Set("User-Agent", profile.UserAgent)
	}
	for name, value := range profile.Headers {
		headers.Set(name, value)
	}
	if request.Host != "" {
		headers.Set("Host", request.Host)
	}
	if request.ContentLength > 0 || request.Header.Get("Content-Length") != "" {
		headers.Set("Content-Length", strconv.FormatInt(request.ContentLength, 10))
		headers.Del("Transfer-Encoding")
	} else if request.Body != nil {
		headers.Del("Content-Length")
		if request.ContentLength < 0 {
			headers.Set("Transfer-Encoding", "chunked")
		}
	}
	written := map[string]bool{}
	writeHeader := func(name string) error {
		canonical := textproto.CanonicalMIMEHeaderKey(name)
		values, ok := headers[canonical]
		if !ok {
			for actual, candidate := range headers {
				if strings.EqualFold(actual, name) {
					canonical, values, ok = actual, candidate, true
					break
				}
			}
		}
		if !ok || written[strings.ToLower(canonical)] {
			return nil
		}
		for _, value := range values {
			if strings.ContainsAny(value, "\r\n") {
				return fmt.Errorf("invalid newline in header %s", canonical)
			}
			if _, err := fmt.Fprintf(writer, "%s: %s\r\n", canonical, value); err != nil {
				return err
			}
		}
		written[strings.ToLower(canonical)] = true
		return nil
	}
	for _, name := range profile.HeaderOrder {
		if err := writeHeader(name); err != nil {
			return err
		}
	}
	remaining := make([]string, 0, len(headers))
	for name := range headers {
		if !written[strings.ToLower(name)] {
			remaining = append(remaining, name)
		}
	}
	sort.Strings(remaining)
	for _, name := range remaining {
		if err := writeHeader(name); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(writer, "\r\n"); err != nil {
		return err
	}
	if request.Body == nil {
		return nil
	}
	if request.ContentLength >= 0 {
		_, err := io.CopyN(writer, request.Body, request.ContentLength)
		if errors.Is(err, io.EOF) && request.ContentLength == 0 {
			return nil
		}
		return err
	}
	buffer := make([]byte, 32*1024)
	for {
		n, readErr := request.Body.Read(buffer)
		if n > 0 {
			if _, err := fmt.Fprintf(writer, "%x\r\n", n); err != nil {
				return err
			}
			if _, err := writer.Write(buffer[:n]); err != nil {
				return err
			}
			if _, err := io.WriteString(writer, "\r\n"); err != nil {
				return err
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				_, err := io.WriteString(writer, "0\r\n\r\n")
				return err
			}
			return readErr
		}
	}
}

func negotiatedProtocol(conn net.Conn) string {
	if tlsConn, ok := conn.(*utls.UConn); ok {
		return tlsConn.ConnectionState().NegotiatedProtocol
	}
	return ""
}

func roundTripH2(upstream net.Conn, request *http.Request, target string, profile profiles.Profile) (*http.Response, error) {
	transport := &http2.Transport{}
	client, err := transport.NewClientConn(upstream)
	if err != nil {
		return nil, fmt.Errorf("create HTTP/2 client connection: %w", err)
	}
	clone := request.Clone(request.Context())
	clone.RequestURI = ""
	clone.URL.Scheme = "https"
	clone.URL.Host = target
	clone.Host = request.Host
	clone.Header = request.Header.Clone()
	removeHopHeaders(clone.Header)
	if profile.UserAgent != "" {
		clone.Header.Set("User-Agent", profile.UserAgent)
	}
	for name, value := range profile.Headers {
		clone.Header.Set(name, value)
	}
	response, err := client.RoundTrip(clone)
	if err != nil {
		return nil, fmt.Errorf("HTTP/2 round trip: %w", err)
	}
	response.Proto = "HTTP/1.1"
	response.ProtoMajor = 1
	response.ProtoMinor = 1
	return response, nil
}

func removeHopHeaders(header http.Header) {
	for _, name := range []string{"Proxy-Connection", "Proxy-Authenticate", "Proxy-Authorization", "Keep-Alive", "TE", "Trailer", "Upgrade"} {
		header.Del(name)
	}
	for _, value := range header.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			header.Del(strings.TrimSpace(name))
		}
	}
	header.Del("Connection")
}

func writeProxyError(writer io.Writer, status int, err error) {
	body := http.StatusText(status) + "\n"
	_, _ = fmt.Fprintf(writer, "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", status, http.StatusText(status), len(body), body)
}

func withDefaultPort(host, port string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(strings.Trim(host, "[]"), port)
}

func duration(raw string) time.Duration {
	d, _ := time.ParseDuration(raw)
	return d
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
