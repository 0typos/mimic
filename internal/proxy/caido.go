package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

const caidoPreface = "MIMIC/1 "
const maxCaidoPreface = 8192

type caidoTarget struct {
	Target  string `json:"target"`
	TLS     bool   `json:"tls"`
	Profile string `json:"profile,omitempty"`
}

func (s *Server) handleCaido(ctx context.Context, downstream net.Conn) error {
	reader := bufio.NewReaderSize(downstream, maxCaidoPreface+1)
	target, err := readCaidoTarget(reader)
	if err != nil {
		return err
	}
	if err := validateTarget(target.Target); err != nil {
		return err
	}
	if target.Profile != "" {
		if _, _, ok := s.state.ProfileForHostAs(target.Target, target.Profile); !ok {
			return fmt.Errorf("unknown profile %q", target.Profile)
		}
	}
	var upstream net.Conn
	if target.TLS {
		upstream, _, err = s.dialer.DialProfile(ctx, target.Target, target.Profile)
	} else {
		snapshot := s.state.Snapshot()
		upstream, err = net.DialTimeout("tcp", target.Target, duration(snapshot.Config.Runtime.ConnectTimeout))
	}
	if err != nil {
		return err
	}
	defer upstream.Close()
	s.state.RequestHandled()
	s.logger.Debug("Caido upstream connection established", "target", target.Target, "tls", target.TLS, "profile", target.Profile)
	if target.TLS && negotiatedProtocol(upstream) == "h2" {
		request, readErr := http.ReadRequest(reader)
		if readErr != nil {
			return fmt.Errorf("read Caido request for HTTP/2 translation: %w", readErr)
		}
		profile, _, _ := s.state.ProfileForHostAs(target.Target, target.Profile)
		response, roundTripErr := roundTripH2(upstream, request, target.Target, profile)
		if roundTripErr != nil {
			return roundTripErr
		}
		defer response.Body.Close()
		return response.Write(downstream)
	}
	return tunnel(ctx, &bufferedConn{Conn: downstream, reader: reader}, upstream)
}

func readCaidoTarget(reader *bufio.Reader) (caidoTarget, error) {
	line, err := reader.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) || len(line) > maxCaidoPreface {
		return caidoTarget{}, fmt.Errorf("Caido preface exceeds %d bytes", maxCaidoPreface)
	}
	if err != nil {
		return caidoTarget{}, fmt.Errorf("read Caido preface: %w", err)
	}
	text := string(line)
	if !strings.HasPrefix(text, caidoPreface) {
		return caidoTarget{}, errors.New("missing MIMIC/1 Caido preface")
	}
	var target caidoTarget
	if err := json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(text, caidoPreface))), &target); err != nil {
		return caidoTarget{}, fmt.Errorf("decode Caido preface: %w", err)
	}
	return target, nil
}

func validateTarget(target string) error {
	host, port, err := net.SplitHostPort(target)
	if err != nil || host == "" || port == "" {
		return fmt.Errorf("target must be an explicit host:port")
	}
	if strings.ContainsAny(target, "\r\n\x00") {
		return errors.New("invalid control character in target")
	}
	return nil
}

func WriteCaidoPreface(writer io.Writer, target string, tls bool, profile string) error {
	payload, err := json.Marshal(caidoTarget{Target: target, TLS: tls, Profile: profile})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(writer, "%s%s\n", caidoPreface, payload)
	return err
}
