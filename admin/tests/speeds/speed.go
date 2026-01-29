package speeds

import (
	"context"
	"crypto/tls"
	"embed"
	"io/fs"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/movsb/gun/pkg/utils"
)

//go:embed root
var _Root embed.FS

func Icons() fs.FS {
	return utils.Must1(fs.Sub(_Root, `root`))
}

type Result struct {
	Latency time.Duration
	Error   error
}

type SiteResults struct {
	Google  Result
	YouTube Result
	GitHub  Result
	BaiDu   Result
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
	request(`www.baidu.com`, &result.BaiDu)

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
