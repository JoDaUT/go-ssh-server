package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"slices"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
)

var (
	errUserNotAllowed = errors.New("user not allowed")
	errUnknownPubKey  = errors.New("unknown pubkey")
)

type SshServer interface {
	Listen() error
	Accept() error
	Close() error
	Addr() net.Addr
}

type sshServerImpl struct {
	cfg          *Cfg
	listener     net.Listener
	sshServerCfg *ssh.ServerConfig
	ctx          context.Context
	cancel       context.CancelFunc
}

func NewSshServer(cfg *Cfg) SshServer {
	ctx, cancel := context.WithCancel(context.Background())
	return &sshServerImpl{
		cfg:    cfg,
		ctx:    ctx,
		cancel: cancel,
	}
}

func (s *sshServerImpl) Listen() error {
	sshServerCfg, err := initServerCfg(s.cfg)
	if err != nil {
		return fmt.Errorf("could not create init server config: %s", err)
	}
	s.sshServerCfg = sshServerCfg
	listener, err := listen(s.cfg)
	if err != nil {
		return fmt.Errorf("could not start listener: %s", err)
	}
	s.listener = listener
	return nil
}

func (s *sshServerImpl) Accept() error {
	return accept(s.sshServerCfg, s.listener, s.ctx)
}

func (s *sshServerImpl) Close() error {
	s.cancel()
	if err := s.listener.Close(); err != nil {
		return fmt.Errorf("error closing listener: %s", err)
	}
	return nil
}

func (s *sshServerImpl) Addr() net.Addr {
	return s.listener.Addr()
}

func pubKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey, authorizedKeys map[string]bool, authorizedUsers []string) (*ssh.Permissions, error) {
	user := conn.User()

	if !slices.Contains(authorizedUsers, user) {
		return nil, errUserNotAllowed
	}

	if authorizedKeys[string(key.Marshal())] {
		return &ssh.Permissions{
			Extensions: map[string]string{
				"pubkey": string(key.Marshal()),
			},
		}, nil
	}
	return nil, errUnknownPubKey
}

func readAuthorizedKeysFile(filepath string) (map[string]bool, error) {
	authorizedKeysBytes, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to load authorized_keys, err: %w", err)
	}

	authorizedKeysMap := map[string]bool{}
	for len(authorizedKeysBytes) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
		if err != nil {
			return nil, fmt.Errorf("public key parsing: %w", err)
		}
		authorizedKeysMap[string(pubKey.Marshal())] = true
		authorizedKeysBytes = rest
	}
	return authorizedKeysMap, nil
}

func getPrivateKeySigner(privateKeyFile string) (ssh.Signer, error) {
	privateBytes, err := os.ReadFile(privateKeyFile)

	if err != nil {
		return nil, fmt.Errorf("error reading private key: %s", err)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)

	if err != nil {
		return nil, fmt.Errorf("error parsing private key: %s", err)
	}

	return private, nil
}

func initServerCfg(cfg *Cfg) (*ssh.ServerConfig, error) {
	authorizedKeys, err := readAuthorizedKeysFile(cfg.AuthorizedKeyFile)

	if err != nil {
		return nil, fmt.Errorf("error reading authorized keys: %w", err)
	}

	serverCfg := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			return pubKeyCallback(conn, key, authorizedKeys, cfg.AuthorizedUsers)
		},
	}

	private, err := getPrivateKeySigner(cfg.PrivateKeyFile)

	if err != nil {
		return nil, fmt.Errorf("error parsing private key: %s", err)
	}

	serverCfg.AddHostKey(private)

	return serverCfg, nil
}

func listen(cfg *Cfg) (net.Listener, error) {
	address := fmt.Sprintf("%s:%s", cfg.Interface, cfg.Port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("error starting listener on %s: %s", address, err)
	}
	return listener, nil
}

func accept(serverCfg *ssh.ServerConfig, listener net.Listener, ctx context.Context) error {
	fmt.Println("listening on:", listener.Addr())
	for {
		conn, err := listener.Accept()
		select {
		case <-ctx.Done():
			fmt.Println("connection stopped")
			return nil
		default:
			if err != nil {
				fmt.Println("error accepting connection: ", err)
				continue
			}
		}

		sConn, chans, reqs, err := ssh.NewServerConn(conn, serverCfg)
		if err != nil {
			fmt.Println("could not establish server connection: ", err)
			continue
		}
		go ssh.DiscardRequests(reqs)

		go handleServerConn(sConn, chans)
	}
}

func handleServerConn(sConn *ssh.ServerConn, chans <-chan ssh.NewChannel) {
	fmt.Printf("started connection: %s\n", sConn.RemoteAddr())
	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			newChan.Reject(ssh.UnknownChannelType, "channel type not supported")
			continue
		}

		ch, reqs, err := newChan.Accept()
		if err != nil {
			fmt.Printf("error handling channel creation request: %s\n", err)
			continue
		}
		go handleRequests(reqs, ch)
	}
}

func handleRequests(in <-chan *ssh.Request, ch ssh.Channel) {
	defer ch.Close()

	var ptyReq *ptyReq

	for req := range in {
		fmt.Println("req type: ", req)
		switch req.Type {
		case "exec":
			var command string
			var ok bool
			if len(req.Payload) > 4 {
				command, _, ok = parseString(req.Payload)
				if !ok {
					fmt.Println("error parsing payload")
					ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
				}
			}
			cmd := exec.Command("/bin/bash", "-c", command)

			stdout, err := cmd.StdoutPipe()
			if err != nil {
				fmt.Println("error setting stdout: ", err)
				return
			}

			stderr, err := cmd.StderrPipe()
			if err != nil {
				fmt.Println("error setting stderr: ", err)
				return
			}
			stdin, err := cmd.StdinPipe()
			if err != nil {
				fmt.Println("error setting stdin: ", err)
				return
			}

			if err = cmd.Start(); err != nil {
				fmt.Println("error executing command: ", err)
				return
			}

			go io.Copy(stdin, ch)
			io.Copy(ch, stdout)
			io.Copy(ch, stderr)

			if err = cmd.Wait(); err != nil {
				fmt.Println("error waiting command to finish: ", err)
				return
			}

			ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
			return
		case "pty-req":
			pty, ok := parsePtyRequest(req.Payload)
			if !ok {
				req.Reply(false, nil)
				continue
			}
			ptyReq = &pty

		case "shell":
			if ptyReq == nil {
				return
			}
			win := pty.Winsize{
				X: uint16(ptyReq.Window.Width),
				Y: uint16(ptyReq.Window.Height),
			}

			cmd := exec.Command("/bin/bash")
			cmd.Env = append(os.Environ(), "TERM="+ptyReq.Term)

			f, err := pty.StartWithSize(cmd, &win)
			if err != nil {
				fmt.Println("error setting pty: ", err)
				req.Reply(false, nil)
				return
			}
			req.Reply(true, nil)

			go func() {
				if _, err := io.Copy(ch, f); err != nil {
					fmt.Println("connection closed: error copying shell output to channel: ", err)
				}
				ch.Close()
			}()
			go func() {
				if _, err := io.Copy(f, ch); err != nil {
					fmt.Println("connection closed: error copying input to shell: ", err)
				}
				f.Close()
			}()

			go func() {
				if err := cmd.Wait(); err != nil {
					fmt.Println("error waiting command: ", err)
					ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
					ch.Close()
					return
				}
			}()

		default:
			fmt.Printf("%s not implemented. Ignoring request\n", req.Type)
		}

	}
}

func parsePtyRequest(payload []byte) (ptyReq, bool) {
	term, rest, ok := parseString(payload)
	if !ok {
		return ptyReq{}, false
	}
	width32, rest, ok := parseUint32(rest)
	if !ok {
		return ptyReq{}, false
	}
	height32, _, ok := parseUint32(rest)
	if !ok {
		return ptyReq{}, false
	}
	pty := ptyReq{
		Term: term,
		Window: window{
			Width:  int(width32),
			Height: int(height32),
		},
	}
	return pty, true
}

type window struct {
	Width  int
	Height int
}

type ptyReq struct {
	Term   string
	Window window
}
