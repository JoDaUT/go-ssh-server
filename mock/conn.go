package mock

import (
	"net"

	"golang.org/x/crypto/ssh"
)

type MockConnMetadata struct {
	UserCallbackFn func() string
}

func (m *MockConnMetadata) User() string {
	return m.UserCallbackFn()
}

func (m *MockConnMetadata) SessionID() []byte {
	panic("not implemented")
}

func (m *MockConnMetadata) ClientVersion() []byte {
	panic("not implemented")
}

func (m *MockConnMetadata) ServerVersion() []byte {
	panic("not implemented")
}

func (m *MockConnMetadata) RemoteAddr() net.Addr {
	panic("not implemented")
}

func (m *MockConnMetadata) LocalAddr() net.Addr {
	panic("not implemented")
}

var _ ssh.ConnMetadata = &MockConnMetadata{}
