package main

import (
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

func Listen(cfg *Cfg) error {

	authorizedKeys, err := readAuthorizedKeysFile(cfg.AuthorizedKeyFile)

	if err != nil {
		return fmt.Errorf("error reading authorized keys: %w", err)
	}

	serverCfg := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			return pubKeyCallback(conn, key, authorizedKeys, cfg.AuthorizedUsers)
		},
	}

	privateBytes, err := os.ReadFile(cfg.PrivateKeyFile)

	if err != nil {
		return fmt.Errorf("error reading private key: %s", err)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)

	if err != nil {
		return fmt.Errorf("error parsing private key")
	}

	serverCfg.AddHostKey(private)

	return listen(serverCfg, cfg)

}

func listen(serverCfg *ssh.ServerConfig, cfg *Cfg) error {
	address := fmt.Sprintf("%s:%d", cfg.Interface, cfg.Port)
	listener, err := net.Listen("tcp", address)

	if err != nil {
		return fmt.Errorf("error starting listener on %s: %s", address, err)
	}

	fmt.Println("listening on port:", address)
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("error accepting connection: ", err)
			continue
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

	var ptyReq *Pty

	for req := range in {
		fmt.Println("process req type: ", req.Type)
		switch req.Type {
		case "exec":
			var command string
			if len(req.Payload) > 4 {
				command = string(req.Payload[4:]) //remove byte corresponding to the payload size (uint32)
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
			ch.Close()
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

func parsePtyRequest(payload []byte) (Pty, bool) {
	term, rest, ok := parseString(payload)
	if !ok {
		return Pty{}, false
	}
	width32, rest, ok := parseUint32(rest)
	if !ok {
		return Pty{}, false
	}
	height32, _, ok := parseUint32(rest)
	if !ok {
		return Pty{}, false
	}
	pty := Pty{
		Term: term,
		Window: Window{
			Width:  int(width32),
			Height: int(height32),
		},
	}
	return pty, true
}

type Window struct {
	Width  int
	Height int
}

type Pty struct {
	Term   string
	Window Window
}
