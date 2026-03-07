package speed

import (
	"context"
	"crypto/tls"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Result struct {
	Latency time.Duration
	Error   error
}

type SiteResults struct {
	Google    Result
	YouTube   Result
	GitHub    Result
	Wikipedia Result
	Netflix   Result
	Baidu     Result
}

func Test(ctx context.Context) SiteResults {
	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	var (
		now = time.Now()
		wg  = sync.WaitGroup{}
	)

	request := func(url string, output *Result) {
		wg.Go(func() {
			output.Error = dialTLS(ctx, url)
			output.Latency = time.Since(now).Truncate(time.Millisecond)
		})
	}

	result := SiteResults{}
	request(`www.google.com`, &result.Google)
	request(`www.youtube.com`, &result.YouTube)
	request(`github.com`, &result.GitHub)
	request(`www.baidu.com`, &result.Baidu)
	request(`www.wikipedia.org`, &result.Wikipedia)
	request(`www.netflix.com`, &result.Netflix)

	wg.Wait()

	return result
}

func dialTLS(ctx context.Context, u string) error {
	if !strings.Contains(u, `://`) {
		u = `http://` + u
	}
	parsed, err := url.Parse(u)
	if err != nil {
		return err
	}
	addr := parsed.Host
	if !strings.Contains(addr, `:`) {
		addr += `:443`
	}
	conn, err := (&tls.Dialer{}).DialContext(ctx, `tcp4`, addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	return nil
}
