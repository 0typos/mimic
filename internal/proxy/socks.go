package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/0typos/mimic/internal/config"
)

const (
	socksVersion      = 5
	socksConnect      = 1
	socksUDPAssociate = 3
)

func (s *Server) handleSOCKS(ctx context.Context, conn net.Conn, definition config.Listener) error {
	reader := bufio.NewReader(conn)
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return err
	}
	if header[0] != socksVersion {
		return errors.New("unsupported SOCKS version")
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(reader, methods); err != nil {
		return err
	}
	noAuth := false
	for _, method := range methods {
		if method == 0 {
			noAuth = true
		}
	}
	if !noAuth {
		_, _ = conn.Write([]byte{5, 0xff})
		return errors.New("SOCKS client did not offer no-auth")
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return err
	}
	request := make([]byte, 3)
	if _, err := io.ReadFull(reader, request); err != nil {
		return err
	}
	if request[0] != 5 || request[2] != 0 {
		return errors.New("invalid SOCKS request")
	}
	target, err := readSOCKSAddress(reader)
	if err != nil {
		writeSOCKSReply(conn, 8, nil)
		return err
	}
	switch request[1] {
	case socksConnect:
		snapshot := s.state.Snapshot()
		upstream, err := net.DialTimeout("tcp", target, duration(snapshot.Config.Runtime.ConnectTimeout))
		if err != nil {
			writeSOCKSReply(conn, 5, nil)
			return err
		}
		defer upstream.Close()
		if err := writeSOCKSReply(conn, 0, upstream.LocalAddr()); err != nil {
			return err
		}
		return tunnel(ctx, &bufferedConn{Conn: conn, reader: reader}, upstream)
	case socksUDPAssociate:
		if definition.UDPListen == "" {
			writeSOCKSReply(conn, 7, nil)
			return errors.New("SOCKS UDP associate is disabled")
		}
		address, _, _ := config.ParseEndpoint(definition.UDPListen, true)
		udpAddress, err := net.ResolveUDPAddr("udp", address)
		if err != nil {
			return err
		}
		if err := writeSOCKSReply(conn, 0, udpAddress); err != nil {
			return err
		}
		_, err = io.Copy(io.Discard, reader)
		return err
	default:
		writeSOCKSReply(conn, 7, nil)
		return fmt.Errorf("unsupported SOCKS command %d", request[1])
	}
}

func readSOCKSAddress(reader io.Reader) (string, error) {
	typeByte := []byte{0}
	if _, err := io.ReadFull(reader, typeByte); err != nil {
		return "", err
	}
	var host string
	switch typeByte[0] {
	case 1:
		buffer := make([]byte, 4)
		if _, err := io.ReadFull(reader, buffer); err != nil {
			return "", err
		}
		host = net.IP(buffer).String()
	case 4:
		buffer := make([]byte, 16)
		if _, err := io.ReadFull(reader, buffer); err != nil {
			return "", err
		}
		host = net.IP(buffer).String()
	case 3:
		length := []byte{0}
		if _, err := io.ReadFull(reader, length); err != nil {
			return "", err
		}
		buffer := make([]byte, int(length[0]))
		if _, err := io.ReadFull(reader, buffer); err != nil {
			return "", err
		}
		host = string(buffer)
	default:
		return "", fmt.Errorf("unsupported SOCKS address type %d", typeByte[0])
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(reader, port); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port)))), nil
}

func writeSOCKSReply(writer io.Writer, status byte, address net.Addr) error {
	ip := net.IPv4zero
	port := 0
	if address != nil {
		host, rawPort, err := net.SplitHostPort(address.String())
		if err == nil {
			if parsed := net.ParseIP(host); parsed != nil {
				ip = parsed
			}
			port, _ = strconv.Atoi(rawPort)
		}
	}
	if v4 := ip.To4(); v4 != nil {
		response := []byte{5, status, 0, 1, v4[0], v4[1], v4[2], v4[3], 0, 0}
		binary.BigEndian.PutUint16(response[8:], uint16(port))
		_, err := writer.Write(response)
		return err
	}
	response := append([]byte{5, status, 0, 4}, ip.To16()...)
	response = append(response, 0, 0)
	binary.BigEndian.PutUint16(response[len(response)-2:], uint16(port))
	_, err := writer.Write(response)
	return err
}
