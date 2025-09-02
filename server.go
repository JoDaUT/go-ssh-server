package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os/exec"
	"slices"
	"sync/atomic"
	"syscall"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
)

const statusOk = 0

type Session struct {
	user string
	ch   ssh.Channel
	reqs <-chan *ssh.Request
}

func (s *Session) close() error {
	return s.ch.Close()
}

type SshServer struct {
	cfg          *Cfg
	listener     net.Listener
	sshServerCfg *ssh.ServerConfig
	ctx          context.Context
	cancel       context.CancelFunc
	passwd       map[string]passwd
}

func NewSshServer(cfg *Cfg) *SshServer {
	ctx, cancel := context.WithCancel(context.Background())
	return &SshServer{
		cfg:    cfg,
		ctx:    ctx,
		cancel: cancel,
	}
}

func (s *SshServer) Init() error {
	passwdMap, err := loadPasswdMap(s.cfg.AuthorizedUsers, s.cfg.PasswdFile)
	if err != nil {
		return fmt.Errorf("error loading users info: %s", err)
	}
	s.passwd = passwdMap

	sshServerCfg, err := s.initServerCfg(s.cfg)
	if err != nil {
		return fmt.Errorf("could not create init server config: %s", err)
	}
	s.sshServerCfg = sshServerCfg

	return nil
}

func (s *SshServer) Listen() error {
	address := fmt.Sprintf("%s:%s", s.cfg.Interface, s.cfg.Port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("error starting listener on %s: %s", address, err)
	}
	s.listener = listener
	return nil
}

func (s *SshServer) Accept() error {
	fmt.Println("listening on:", s.listener.Addr())
	for {
		conn, err := s.listener.Accept()
		select {
		case <-s.ctx.Done():
			fmt.Println("connection stopped")
			return nil
		default:
			if err != nil {
				fmt.Println("error accepting connection: ", err)
				continue
			}
		}

		sConn, chans, reqs, err := ssh.NewServerConn(conn, s.sshServerCfg)
		if err != nil {
			fmt.Println("could not establish server connection: ", err)
			continue
		}
		go ssh.DiscardRequests(reqs)

		go s.handleServerConn(sConn, chans)
	}
}

func (s *SshServer) Close() error {
	s.cancel()
	if s.listener == nil {
		return nil
	}
	if err := s.listener.Close(); err != nil {
		return fmt.Errorf("error closing listener: %s", err)
	}
	return nil
}

func (s *SshServer) Addr() net.Addr {
	return s.listener.Addr()
}

func (s *SshServer) initServerCfg(cfg *Cfg) (*ssh.ServerConfig, error) {
	authorizedKeys, err := readAuthorizedKeysFile(cfg.AuthorizedKeyFile)

	if err != nil {
		return nil, fmt.Errorf("error reading authorized keys: %w", err)
	}

	users := make([]string, len(s.passwd))
	for username, _ := range s.passwd {
		users = append(users, username)
	}

	serverCfg := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			return pubKeyCallback(conn.User(), key, authorizedKeys, users)
		},
	}

	private, err := getPrivateKeySigner(cfg.PrivateKeyFile)

	if err != nil {
		return nil, fmt.Errorf("error parsing private key: %s", err)
	}

	serverCfg.AddHostKey(private)

	return serverCfg, nil
}

func (s *SshServer) handleServerConn(sConn *ssh.ServerConn, chans <-chan ssh.NewChannel) {
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
		session := Session{
			user: sConn.User(),
			ch:   ch,
			reqs: reqs,
		}
		go s.handleRequests(session)
	}
}

func (s *SshServer) handleRequests(session Session) {
	defer session.close()
	var ptyReq *ptyReq
	var envVars []string
	var closed atomic.Bool

	for req := range session.reqs {
		switch req.Type {
		case "env":
			envVar, rest, ok := parseString(req.Payload)
			if !ok {
				fmt.Println("error parsing payload")
				req.Reply(false, nil)
				continue
			}
			if len(rest) == 0 {
				fmt.Println("error parsing payload")
				req.Reply(false, nil)
				continue
			}
			envVarValue, _, ok := parseString(rest)
			if !ok {
				fmt.Println("error parsing payload")
				req.Reply(false, nil)
				continue
			}
			req.Reply(true, nil)
			envVars = append(envVars, envVar+"="+envVarValue)
		case "exec":
			command, _, ok := parseString(req.Payload)
			if !ok {
				fmt.Println("error parsing payload")
				req.Reply(false, nil)
				return
			}

			userInfo, ok := s.passwd[session.user]
			if !ok {
				req.Reply(false, nil)
				fmt.Printf("could not find info for user %s in userMap\n", session.user)
				return
			}

			req.Reply(true, nil)
			cmd := exec.Command(userInfo.shell, "-c", command)
			cmd.Env = envVars
			cmd.Dir = userInfo.home
			cmd.SysProcAttr = &syscall.SysProcAttr{}
			cmd.SysProcAttr.Credential = &syscall.Credential{
				Uid: userInfo.uid,
				Gid: userInfo.gid,
			}

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

			go io.Copy(stdin, session.ch)
			io.Copy(session.ch, stdout)
			io.Copy(session.ch, stderr)

			if err = cmd.Wait(); err != nil {
				fmt.Println("error waiting command to finish: ", err)
				return
			}
			s.sendExitStatus(session.ch, &closed)
		case "pty-req":
			pty, ok := parsePtyRequest(req.Payload)
			if !ok {
				req.Reply(false, nil)
				continue
			}
			req.Reply(true, nil)
			ptyReq = &pty
		case "shell":
			if ptyReq == nil {
				req.Reply(false, nil)
				return
			}

			userInfo, ok := s.passwd[session.user]
			if !ok {
				req.Reply(false, nil)
				fmt.Printf("could not find info for user %s in userMap\n", session.user)
				return
			}

			req.Reply(true, nil)
			win := pty.Winsize{
				X: uint16(ptyReq.Window.Width),
				Y: uint16(ptyReq.Window.Height),
			}

			cmd := exec.Command(userInfo.shell)
			envVars = append(envVars, "TERM="+ptyReq.Term)
			cmd.Env = append(cmd.Env, envVars...)
			cmd.Dir = userInfo.home
			cmd.SysProcAttr = &syscall.SysProcAttr{}
			cmd.SysProcAttr.Credential = &syscall.Credential{
				Uid: userInfo.uid,
				Gid: userInfo.gid,
			}

			terminal, err := pty.StartWithSize(cmd, &win)
			if err != nil {
				fmt.Println("error setting pty: ", err)
				return
			}

			go func() {
				defer session.close()
				if _, err := io.Copy(session.ch, terminal); err != nil {
					fmt.Println("connection closed: error copying shell output to channel: ", err)
				}
				s.sendExitStatus(session.ch, &closed)
			}()
			go func() {
				defer terminal.Close()
				if _, err := io.Copy(terminal, session.ch); err != nil {
					fmt.Println("connection closed: error copying input to shell: ", err)
				}
				s.sendExitStatus(session.ch, &closed)
			}()

			go func() {
				if err := cmd.Wait(); err != nil {
					fmt.Println("error waiting command: ", err)
					return
				}
				s.sendExitStatus(session.ch, &closed)
			}()
		default:
			fmt.Printf("%s not implemented. Ignoring request\n", req.Type)
			req.Reply(false, nil)
		}

		if closed.Load() {
			if err := session.close(); err != nil {
				fmt.Println("error closing session: ", err)
			}
		}
	}
}

// sends exist-status and updates the atomic closed flag ensuring the message is sent once
func (s *SshServer) sendExitStatus(ch ssh.Channel, closed *atomic.Bool) {
	if closed.Load() {
		return
	}
	ch.SendRequest("exit-status", false, uint32ToBytes(uint32(statusOk)))
	closed.Store(true)
}

func pubKeyCallback(user string, key ssh.PublicKey, authorizedKeys map[string]bool, authorizedUsers []string) (*ssh.Permissions, error) {
	if !slices.Contains(authorizedUsers, user) {
		return nil, fmt.Errorf("user not allowed")
	}

	if authorizedKeys[ssh.FingerprintSHA256(key)] {
		return &ssh.Permissions{
			Extensions: map[string]string{
				"pubkey": string(key.Marshal()),
			},
		}, nil
	}
	return nil, fmt.Errorf("unknown public key")
}
