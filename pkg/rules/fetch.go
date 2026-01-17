package rules

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/movsb/gun/pkg/utils"
)

const (
	chinaDomainsURL  = `https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf`
	ChinaDomainsName = `china.domains.ro.txt`

	gfwDomainsURL  = `https://raw.githubusercontent.com/pexcn/daily/gh-pages/gfwlist/gfwlist.txt`
	GfwDomainsName = `banned.domains.ro.txt`

	// 合并后的中国路由列表，含IPv4和IPv6。
	chinaRoutesURL  = `https://ftp.apnic.net/stats/apnic/delegated-apnic-latest`
	ChinaRoutesName = `china.routes.ro.txt`

	BannedUserTxt  = `banned.user.txt`
	IgnoredUserTxt = `ignored.user.txt`
)

func UpdateChinaDomains(ctx context.Context) {
	_safelySaveURLAsFile(ctx, chinaDomainsURL, ChinaDomainsName, func(w io.Writer, r io.Reader) error {
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			// server=/qq.com/114.114.114.114
			parts := strings.Split(scanner.Text(), `/`)
			if len(parts) != 3 {
				continue
			}
			utils.Must1(fmt.Fprintln(w, parts[1]))
		}
		return scanner.Err()
	})
}

func UpdateGFWDomains(ctx context.Context) {
	_safelySaveURLAsFile(ctx, gfwDomainsURL, GfwDomainsName, func(w io.Writer, r io.Reader) error {
		_, err := io.Copy(w, r)
		return err
	})
}

func UpdateChinaRoutes(ctx context.Context) {
	_safelySaveURLAsFile(ctx, chinaRoutesURL, ChinaRoutesName, func(w io.Writer, r io.Reader) error {
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			line := scanner.Text()

			if strings.Contains(line, `|CN|ipv4|`) {
				parts := strings.Split(line, `|`)
				if len(parts) < 5 {
					continue
				}

				start := parts[3]
				count := utils.Must1(strconv.Atoi(parts[4]))
				bits := 32 - int(math.Log2(float64(count)))
				utils.Must1(fmt.Fprintf(w, "%s/%d\n", start, bits))

				continue
			}

			if strings.Contains(line, `|CN|ipv6|`) {
				parts := strings.Split(line, `|`)
				if len(parts) < 5 {
					continue
				}

				prefix := parts[3]
				bits := utils.Must1(strconv.Atoi(parts[4]))
				utils.Must1(fmt.Fprintf(w, "%s/%d\n", prefix, bits))

				continue
			}

			// ignored another lines.
		}
		return scanner.Err()
	})
}

// 安全下载URL到Path，通过copy函数拷贝。
//
//   - 但是并没有校验每一行数据是否合法。
func _safelySaveURLAsFile(ctx context.Context, url string, path string, transform func(w io.Writer, r io.Reader) error) {
	req := utils.Must1(http.NewRequestWithContext(ctx, http.MethodGet, url, nil))
	rsp := utils.Must1(http.DefaultClient.Do(req))
	if rsp.StatusCode != 200 {
		log.Panicln(`下载时失败：`, rsp.Status)
	}
	defer rsp.Body.Close()

	// 直接在当前目录创建临时文件，以避免 os.Rename 的跨文件系统边界
	// 重命名文件时报错。
	tmpFile := utils.Must1(os.CreateTemp(`.`, `.*.tmp`))
	defer func() {
		if tmpFile != nil {
			tmpFile.Close()
			os.Remove(tmpFile.Name())
		}
	}()

	if err := transform(tmpFile, rsp.Body); err != nil {
		log.Panicln(err)
	}

	if err := tmpFile.Close(); err != nil {
		log.Panicln(err)
	}

	// 正常来说应该有很多行，异常情况可能是个小文件。
	if info, err := os.Stat(tmpFile.Name()); err != nil || info.Size() <= 1<<10 {
		log.Panicln(`数据文件有误：`, errors.Join(err, fmt.Errorf(`文件大小：%d`, info.Size())))
	}

	if err := os.Rename(tmpFile.Name(), path); err != nil {
		log.Panicln(`重命名文件时出错：`, err)
	}

	tmpFile = nil
}
