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
	"go4.org/netipx"
)

func init() {
	utils.Must(ipset.Init())
}

// 一个基于内存的DNS服务器。
//
// 这里面的大部分数据库结构都没有加锁，
// 所以只能一次性初始化完成，不能运行时修改。
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

	chinaRoutes *netipx.IPSet

	// 被屏蔽的完整域名。
	blockedDomains map[string]struct{}

	whiteSet4, blackSet4 string
	whiteSet6, blackSet6 string

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
	chinaRoutes []string, blockedDomains []string,
	whiteSet4, blackSet4, whiteSet6, blackSet6 string,
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
		blockedDomains:       map[string]struct{}{},
		chinaRoutes:          &netipx.IPSet{},

		whiteSet4: whiteSet4,
		blackSet4: blackSet4,
		whiteSet6: whiteSet6,
		blackSet6: blackSet6,
	}

	// 需要绑定到所有接口才能接受来自 --redirect --to-ports 的请求。
	// 否则可能表现为：能收到路由器本身的DNS请求、收不到局域网其它主机的请求。
	s.srv = &dns.Server{
		Net:     `udp4`,
		Addr:    fmt.Sprintf(`0.0.0.0:%d`, port),
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
	for _, d := range blockedDomains {
		s.blockedDomains[d] = struct{}{}
	}

	ipSetBuilder := netipx.IPSetBuilder{}
	for _, r := range chinaRoutes {
		if strings.IndexByte(r, '/') < 0 {
			ip := netip.MustParseAddr(r)
			ipSetBuilder.Add(ip)
		} else {
			prefix := netip.MustParsePrefix(r)
			ipSetBuilder.AddPrefix(prefix)
		}
	}
	s.chinaRoutes = utils.Must1(ipSetBuilder.IPSet())

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
	// 先检查是否处于屏蔽列表中。
	if s.handleBlocked(w, r) {
		return
	}

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

func (s *Server) handleBlocked(w dns.ResponseWriter, r *dns.Msg) bool {
	q := r.Question[0]
	d := strings.TrimSuffix(q.Name, `.`)
	if _, ok := s.blockedDomains[d]; !ok {
		return false
	}
	msg := dns.Msg{}
	msg.SetRcode(r, dns.RcodeNameError)
	w.WriteMsg(&msg)
	log.Println(`屏蔽了域名访问：`, d)
	return true
}

func (s *Server) handleChina(w dns.ResponseWriter, r *dns.Msg) {
	log.Println(`处理中国请求：`, questionStrings(r.Question))
	rsp, _, err := s.udp.Exchange(r, s.chinaUpstream)
	if err != nil {
		log.Println(err, questionStrings(r.Question))
		dns.HandleFailed(w, r)
		return
	}
	if rsp.Rcode != dns.RcodeSuccess {
		log.Println(`请求不成功：`, r, rsp)
		return
	}
	s.saveIPSet(rsp, true)
	s.saveCache(r.Question[0], rsp)
	w.WriteMsg(rsp)
}

func (s *Server) handleBanned(w dns.ResponseWriter, r *dns.Msg) {
	log.Println(`处理外国请求：`, questionStrings(r.Question))
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
	s.saveIPSet(rsp, false)
	s.saveCache(r.Question[0], rsp)
	w.WriteMsg(rsp)
}

func (s *Server) handleDetect(w dns.ResponseWriter, r *dns.Msg) {
	log.Println(`处理检测请求：`, questionStrings(r.Question))

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
	if chinaErr == nil && chinaRsp.Rcode == dns.RcodeSuccess && len(chinaRsp.Answer) > 0 {
		allInChina := true
		for _, ans := range chinaRsp.Answer {
			switch ans.Header().Rrtype {
			case dns.TypeA:
				a := ans.(*dns.A)
				ip, _ := netip.AddrFromSlice(a.A)
				white := s.chinaRoutes.Contains(ip)
				allInChina = allInChina && white
			}
		}
		if allInChina {
			s.saveIPSet(chinaRsp, true)
			s.saveCache(r.Question[0], chinaRsp)
			w.WriteMsg(chinaRsp)
			log.Printf("检测为中国地址：\n%s\n%s", questionStrings(r.Question), answerStrings(chinaRsp.Answer))
			return
		}
	}

	if bannedErr == nil && bannedRsp.Rcode == dns.RcodeSuccess && len(bannedRsp.Answer) > 0 {
		s.saveIPSet(bannedRsp, false)
		s.saveCache(r.Question[0], bannedRsp)
		w.WriteMsg(bannedRsp)
		log.Printf("检测为外国地址：\n%s\n%s", questionStrings(r.Question), answerStrings(bannedRsp.Answer))
		return
	}

	// 随便返回一个即可。
	if rsp := utils.IIF(chinaRsp != nil, chinaRsp, bannedRsp); rsp != nil {
		w.WriteMsg(rsp)
		log.Println(`检测失败：`, questionStrings(r.Question), answerStrings(rsp.Answer))
	} else {
		dns.HandleFailed(w, r)
	}
}

// 注意：没有设置过期时间。
func (s *Server) saveIPSet(rsp *dns.Msg, white bool) {
	for _, ans := range rsp.Answer {
		switch ans.Header().Rrtype {
		case dns.TypeA:
			a := ans.(*dns.A)
			ip, _ := netip.AddrFromSlice(a.A)
			set := utils.IIF(white, s.whiteSet4, s.blackSet4)
			if err := ipset.AddAddr(set, ip); err != nil {
				log.Println(`未能将IP添加到名单：`, set, err)
			} else {
				log.Println(`已将IP添加到名单：`, set, ip)
			}
		case dns.TypeAAAA:
			a := ans.(*dns.AAAA)
			ip, _ := netip.AddrFromSlice(a.AAAA)
			set := utils.IIF(white, s.whiteSet6, s.blackSet6)
			if err := ipset.AddAddr(set, ip, ipset.OptIPv6()); err != nil {
				log.Println(`未能将IP添加到名单：`, set, err)
			} else {
				log.Println(`已将IP添加到名单：`, set, ip)
			}
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

func questionStrings(qs []dns.Question) string {
	var s []string
	for _, q := range qs {
		s = append(s, q.String())
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
