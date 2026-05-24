package subscriptions

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"net/url"
	urlpkg "net/url"

	"github.com/movsb/gun/cmd/configs"
)

// [机场订阅标准介绍 - 觅云🔥](https://wiki.miyun.app/subscribe.html)
// [subconverter/README-cn.md at master · tindy2013/subconverter](https://github.com/tindy2013/subconverter/blob/master/README-cn.md)

// 不知道这是哪家的订阅格式，返回的全部是 trojan。
// https://host/api/v1/client/subscribe?token=xxx

func ParseSubscription(ctx context.Context, url string) (map[string]configs.OutputConfig, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf(`无效的链接：%w`, err)
	}
	rsp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf(`请求失败：%w`, err)
	}
	defer rsp.Body.Close()
	if rsp.StatusCode != 200 {
		return nil, fmt.Errorf(`状态码不正确：%v`, rsp.Status)
	}

	body := io.LimitReader(rsp.Body, 1<<20)
	// 整体被 base64 编码过。
	base64Decoder := base64.NewDecoder(base64.StdEncoding, body)
	// 每行一个URL。
	lineScanner := bufio.NewScanner(base64Decoder)

	// key是从url推断出来的节点名字。
	outputs := map[string]configs.OutputConfig{}

	for lineScanner.Scan() {
		line := lineScanner.Text()
		parsed, err := urlpkg.Parse(line)
		if err != nil {
			return nil, fmt.Errorf(`无法解析为URL：%s: %w`, line, err)
		}
		query := parsed.Query()
		switch parsed.Scheme {
		default:
			return nil, fmt.Errorf(`未知协议：%s`, parsed.Scheme)
		case `trojan`:
			name, tr, err := parseTrojan(parsed, query, line)
			if err != nil {
				return nil, err
			}
			outputs[name] = configs.OutputConfig{Trojan: tr}
		}
	}

	if lineScanner.Err() != nil {
		return nil, fmt.Errorf(`解析订阅失败：%w`, lineScanner.Err())
	}

	return outputs, nil
}

func parseTrojan(parsed *url.URL, query url.Values, raw string) (string, *configs.TrojanOutputConfig, error) {
	tr := configs.TrojanOutputConfig{}

	// 离谱的是这群人把密码存在url的username位置。
	username := parsed.User.Username()
	if username == `` {
		return ``, nil, fmt.Errorf(`没有密码，链接格式错误：%s`, raw)
	}
	tr.Password = username

	// 正常来说，一定有端口号。
	host := parsed.Host
	_, _, err := net.SplitHostPort(host)
	if err != nil {
		return ``, nil, fmt.Errorf(`服务器地址不正确：%w`, err)
	}
	tr.Server = host

	tr.Insecure = query.Get(`allowInsecure`) == `1`

	sni := query.Get(`sni`)
	if sni == `` {
		sni = query.Get(`peer`)
	}
	tr.SNI = sni

	name := parsed.Fragment
	if name == `` {
		name = hash(tr.Server, tr.Password, tr.Insecure, tr.SNI)
	}

	return name, &tr, nil
}

// 如果没有设定名字（不应该），则根据参数尽量hash出来一个不会重复的名字。
func hash(prefix string, keys ...any) string {
	buf := bytes.NewBuffer(nil)
	for _, key := range keys {
		fmt.Fprintln(buf, key)
	}
	sum := fnv.New32a()
	sum.Write(buf.Bytes())
	return fmt.Sprintf(`%s: %08x`, prefix, sum.Sum32())
}
