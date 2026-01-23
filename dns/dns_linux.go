//go:build linux

package dns

import (
	"fmt"
	"iter"
	"log"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/movsb/gun/pkg/utils"
	"github.com/nadoo/ipset"
	"github.com/phuslu/lru"
	"github.com/yl2chen/cidranger"
)

func init() {
	utils.Must(ipset.Init())
}

// 一个基于内存的DNS服务器。
type Server struct {
	srv *dns.Server
	mux *dns.ServeMux

	// 国外走TCP。
	tcp *dns.Client
	// 国内走UDP。
	udp *dns.Client

	chinaUpstream  string
	bannedUpstream string

	// 没有加最后的 . 的域名后缀列表。
	chinaDomainsSuffixes map[string]struct{}
	bannedDomainSuffixes map[string]struct{}

	chinaRoutes cidranger.Ranger

	whiteSet4 string
	blackSet4 string

	cache *lru.TTLCache[cacheKey, cacheValue]
}

type cacheKey struct {
	name  string
	typ   dns.Type
	class dns.Class
}

type cacheValue struct {
	msg *dns.Msg
}

func NewServer(port int,
	chinaUpstream, bannedUpstream string,
	chinaDomains, bannedDomains []string,
	chinaRoutes []netip.Prefix,
	whiteSet4, blackSet4 string,
) *Server {
	addPort := func(s string, port uint16) string {
		_, _, err := net.SplitHostPort(s)
		if err == nil {
			return s
		}
		return net.JoinHostPort(s, fmt.Sprint(port))
	}

	s := &Server{
		mux:   dns.NewServeMux(),
		cache: lru.NewTTLCache[cacheKey, cacheValue](1024),

		chinaUpstream:  addPort(chinaUpstream, 53),
		bannedUpstream: addPort(bannedUpstream, 53),

		chinaDomainsSuffixes: map[string]struct{}{},
		bannedDomainSuffixes: map[string]struct{}{},
		chinaRoutes:          cidranger.NewPCTrieRanger(),

		whiteSet4: whiteSet4,
		blackSet4: blackSet4,
	}

	s.srv = &dns.Server{
		Net:     `udp`,
		Addr:    fmt.Sprintf(`127.0.0.1:%d`, port),
		Handler: s.mux,
	}
	s.tcp = &dns.Client{
		Net: `tcp`,
	}
	s.udp = &dns.Client{
		Net: `udp`,
	}
	s.mux.HandleFunc(`.`, s.handleCached)

	for _, d := range chinaDomains {
		s.chinaDomainsSuffixes[d] = struct{}{}
	}
	for _, d := range bannedDomains {
		s.bannedDomainSuffixes[d] = struct{}{}
	}
	for _, r := range chinaRoutes {
		ip := net.IP(r.Addr().AsSlice())
		mask := net.CIDRMask(r.Bits(), r.Addr().BitLen())
		entry := cidranger.NewBasicRangerEntry(net.IPNet{
			IP:   ip,
			Mask: mask,
		})
		s.chinaRoutes.Insert(entry)
	}

	return s
}

func (s *Server) ListenAndServe() error {
	return s.srv.ListenAndServe()
}

func (s *Server) handleCached(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) != 1 {
		log.Println(`查询问题多于一个，未处理的请求`, r)
		s.handleFallback(w, r)
		return
	}
	q := r.Question[0]
	key := cacheKey{
		name:  q.Name,
		typ:   dns.Type(q.Qtype),
		class: dns.Class(q.Qclass),
	}
	val, _, found := s.cache.Peek(key)
	if found {
		rsp := val.msg.Copy()
		rsp.Id = r.Id
		w.WriteMsg(rsp)
		log.Println(`使用缓存`, key.name, key.typ.String())
		return
	}

	// 优化：这里尚没有加锁，可能重复查询一个域名多次，然后缓存。
	s.handle(w, r)
}

func (s *Server) handle(w dns.ResponseWriter, r *dns.Msg) {
	q := r.Question[0]
	if q.Qclass == dns.ClassINET {
		if q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA {
			for suffix := range split(q.Name) {
				_, inChina := s.chinaDomainsSuffixes[suffix]
				if inChina {
					s.handleChina(w, r)
					return
				}
				_, banned := s.bannedDomainSuffixes[suffix]
				if banned {
					s.handleBanned(w, r)
					return
				}
			}
			// 查询了一个既不在国内也不在国外列表内的域名。
			// 分别向两个服务器查询，如果中国服务器返回的IP在路由范围内，
			// 则使用中国的，否则使用外国的。
			s.handleDetect(w, r)
			return
		}
	}

	s.handleFallback(w, r)
}

func (s *Server) handleChina(w dns.ResponseWriter, r *dns.Msg) {
	log.Println(`处理中国请求：`, r.Question[0].String())
	rsp, _, err := s.udp.Exchange(r, s.chinaUpstream)
	if err != nil {
		log.Println(err, r)
		dns.HandleFailed(w, r)
		return
	}
	if rsp.Rcode != dns.RcodeSuccess {
		log.Println(`请求不成功：`, r, rsp)
		return
	}
	s.saveIPSet(rsp)
	s.saveCache(r.Question[0], rsp)
	w.WriteMsg(rsp)
}

func (s *Server) handleBanned(w dns.ResponseWriter, r *dns.Msg) {
	log.Println(`处理外国请求：`, r.Question[0])
	rsp, _, err := s.tcp.Exchange(r, s.bannedUpstream)
	if err != nil {
		log.Println(err, r)
		dns.HandleFailed(w, r)
		return
	}
	if rsp.Rcode != dns.RcodeSuccess {
		log.Println(`请求不成功：`, r, rsp)
		return
	}
	s.saveIPSet(rsp)
	s.saveCache(r.Question[0], rsp)
	w.WriteMsg(rsp)
}

func (s *Server) handleDetect(w dns.ResponseWriter, r *dns.Msg) {
	log.Println(`处理检测请求：`, r.Question[0])

	ch := make(chan struct{}, 2)

	var chinaRsp *dns.Msg
	var chinaErr error
	go func() {
		chinaRsp, _, chinaErr = s.udp.Exchange(r.Copy(), s.chinaUpstream)
		ch <- struct{}{}
	}()
	var bannedRsp *dns.Msg
	var bannedErr error
	go func() {
		bannedRsp, _, bannedErr = s.tcp.Exchange(r.Copy(), s.bannedUpstream)
		ch <- struct{}{}
	}()

	_ = <-ch
	_ = <-ch

	// 中国的服务器响应了处于中国路由范围内的IP地址，被简单认为是中国IP。
	if chinaErr == nil && chinaRsp.Rcode == dns.RcodeSuccess {
		allInChina := true
		for _, ans := range chinaRsp.Answer {
			switch ans.Header().Rrtype {
			case dns.TypeA:
				a := ans.(*dns.A)
				white, _ := s.chinaRoutes.Contains(a.A)
				allInChina = allInChina && white
			}
		}
		if allInChina {
			s.saveIPSet(chinaRsp)
			s.saveCache(r.Question[0], chinaRsp)
			w.WriteMsg(chinaRsp)
			log.Println(`检测为中国地址：`, r, answerStrings(chinaRsp.Answer))
			return
		}
	}

	if bannedErr == nil && bannedRsp.Rcode == dns.RcodeSuccess {
		s.saveIPSet(bannedRsp)
		s.saveCache(r.Question[0], bannedRsp)
		w.WriteMsg(bannedRsp)
		log.Println(`检测为外国地址：`, r, answerStrings(bannedRsp.Answer))
		return
	}

	log.Println(`检测失败：`, r)
	dns.HandleFailed(w, r)
}

// 注意：没有设置过期时间。
func (s *Server) saveIPSet(rsp *dns.Msg) {
	for _, ans := range rsp.Answer {
		switch ans.Header().Rrtype {
		case dns.TypeA:
			a := ans.(*dns.A)
			ip, _ := netip.AddrFromSlice(a.A)
			white, _ := s.chinaRoutes.Contains(a.A)
			set := utils.IIF(white, s.whiteSet4, s.blackSet4)
			if err := ipset.AddAddr(set, ip); err != nil {
				log.Println(`未能将IP添加到名单：`, set, err)
			} else {
				log.Println(`已将IP添加到名单：`, set, ip)
			}
		default:
			log.Println(`未设置到IPSet：`, rsp)
		}
	}
}

func (s *Server) saveCache(q dns.Question, rsp *dns.Msg) {
	minTTL := uint32(300)
	for _, rr := range rsp.Answer {
		ttl := rr.Header().Ttl
		if ttl < minTTL {
			minTTL = ttl
		}
	}
	if minTTL <= 0 {
		return
	}
	if minTTL < 300 {
		minTTL = 300
	}

	key := cacheKey{
		name:  q.Name,
		typ:   dns.Type(q.Qtype),
		class: dns.Class(q.Qclass),
	}
	s.cache.Set(key, cacheValue{
		// 好像可以不用复制。
		rsp.Copy(),
	}, time.Duration(time.Duration(minTTL)*time.Second))
	log.Printf("写入缓存：%v %s\n%s", key.name, key.typ.String(), answerStrings(rsp.Answer))
}

func answerStrings(ans []dns.RR) string {
	var s []string
	for _, a := range ans {
		s = append(s, a.String())
	}
	return strings.Join(s, "\n")
}

// 把域名拆成后缀用于依次匹配。
// abc.example.com. -> [abc.example.com, example.com, com]
func split(domain string) iter.Seq[string] {
	if domain[len(domain)-1] == '.' {
		domain = domain[0 : len(domain)-1]
	}
	return func(yield func(string) bool) {
		if !yield(domain) {
			return
		}
		for {
			dot := strings.IndexByte(domain, '.')
			if dot < 0 {
				return
			}
			remain := domain[dot+1:]
			if len(remain) <= 0 {
				return
			}
			if !yield(remain) {
				return
			}
			domain = remain
		}
	}
}

func (s *Server) handleFallback(w dns.ResponseWriter, r *dns.Msg) {
	resp, _, err := s.udp.Exchange(r, s.chinaUpstream)
	if err != nil {
		log.Println("dns forward error:", err)
		dns.HandleFailed(w, r)
		return
	}
	w.WriteMsg(resp)
}
