package ssh

import (
	"fmt"
	"log"
	"net"

	"github.com/movsb/gun/pkg/tproxy"
	"github.com/movsb/gun/pkg/utils"
	"golang.org/x/crypto/ssh"
)

type SSH struct {
	client *ssh.Client
}

func New(username, password string, addrPort string) *SSH {
	config := ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{ssh.Password(password)},
		// TODO 不应该忽略主机校验。
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client := utils.Must1(ssh.Dial(`tcp4`, addrPort, &config))
	return &SSH{client: client}
}

func (s *SSH) Serve(local net.Conn, dstAddr string) error {
	defer local.Close()

	remote, err := s.client.Dial(`tcp4`, dstAddr)
	if err != nil {
		return fmt.Errorf(`ssh: dial: %s: %w`, dstAddr, err)
	}
	defer remote.Close()

	utils.Stream(local, remote)

	return nil
}

func (s *SSH) ListenAndServeTProxy(port uint16) {
	tproxy.ListenAndServeTCP(port, func(conn net.Conn) {
		dstAddr := conn.LocalAddr().String()
		if err := s.Serve(conn, dstAddr); err != nil {
			log.Println(err)
		}
	})
}
