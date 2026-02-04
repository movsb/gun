package cmd

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/movsb/gun/pkg/rules"
	"github.com/movsb/gun/pkg/utils"
	"github.com/movsb/gun/targets"
	"github.com/movsb/gun/targets/alpine"
	"github.com/movsb/gun/targets/openwrt"
	"github.com/movsb/gun/targets/ubuntu"
	"github.com/spf13/cobra"
)

func cmdSetup(cmd *cobra.Command, args []string) {
	mustBeRoot()

	configDir := getConfigDir(cmd)
	utils.Must(os.MkdirAll(configDir, 0700))

	distro, version := targets.GuessTarget()
	if distro == `` {
		log.Fatalln(`无法推断出系统类型，无法完成自动安装。`)
	}

	switch distro {
	case `openwrt`:
		// 24 及以前版本使用 opkg
		if version.Major <= 24 {
			openwrt.Opkg()
			return
		}
		// 25 及以后使用 apk。
		if version.Major >= 25 {
			openwrt.Apk()
			return
		}
	case `ubuntu`:
		ubuntu.Apt()
		return
	case `alpine`:
		alpine.Apk()
		return
	}

	log.Println(`啥也没干。`)
}

func cmdUpdate(cmd *cobra.Command, args []string) {
	ctx := cmd.Context()
	fmt.Println(`正在尝试更新所有的规则配置文件...`)
	time.Sleep(time.Millisecond * 500)

	configDir := getConfigDir(cmd)

	fmt.Println(`正在更新中国域名列表...`)
	rules.UpdateChinaDomains(ctx, configDir)

	fmt.Println(`正在更新被墙域名列表...`)
	rules.UpdateGFWDomains(ctx, configDir)

	fmt.Println(`正在更新中国路由列表...`)
	rules.UpdateChinaRoutes(ctx, configDir)

	if f := filepath.Join(configDir, rules.BannedUserTxt); !utils.FileExists(f) {
		fmt.Println(`写入被墙的额外列表...`)
		utils.Must(os.WriteFile(f, rules.BannedDefaultText, 0644))
	}
	if f := filepath.Join(configDir, rules.IgnoredUserTxt); !utils.FileExists(f) {
		fmt.Println(`写入直连的额外列表...`)
		utils.Must(os.WriteFile(f, rules.IgnoredDefaultText, 0644))
	}
	if f := filepath.Join(configDir, rules.BlockedUserTxt); !utils.FileExists(f) {
		fmt.Println(`写入默认被屏蔽的域名列表...`)
		utils.Must(os.WriteFile(f, rules.BlockedDefaultTxt, 0644))
	}
}
