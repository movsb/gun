//go:build !linux

package dns

import "net/netip"

type Server struct{}

func NewServer(port int,
	chinaUpstream, bannedUpstream string,
	chinaDomains, bannedDomains []string,
	chinaRoutes []netip.Prefix,
	whiteSet4, blackSet4 string,
) *Server {
	panic(`not for non-linux`)
}

func (Server) ListenAndServe() error {
	panic(`error`)
}
