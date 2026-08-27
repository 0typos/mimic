package proxy

import (
	"context"
	"errors"
	"io"
	"net"
)

func allowed(remote net.Addr, cidrs []string) bool {
	if len(cidrs) == 0 {
		return true
	}
	host, _, err := net.SplitHostPort(remote.String())
	if err != nil {
		return remote.Network() == "unix"
	}
	ip := net.ParseIP(host)
	for _, raw := range cidrs {
		_, network, _ := net.ParseCIDR(raw)
		if network != nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func tunnel(ctx context.Context, left, right net.Conn) error {
	result := make(chan error, 2)
	copyOne := func(dst, src net.Conn) {
		_, err := io.Copy(dst, src)
		if closer, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = closer.CloseWrite()
		}
		result <- err
	}
	go copyOne(left, right)
	go copyOne(right, left)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-result:
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	}
}
