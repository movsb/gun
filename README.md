# gun

我自己实现并一直使用的一个小工具，用于在路由器(OpenWRT)或内网小主机上透明代理流量（仅限Linux系统）。

简单、稳定为主，功能为辅。

## 使用方式

```bash
$ gun
Usage:
  gun [command]

Available Commands:
  setup       推测系统版本并安装必要的系统工具和规则文件。
  start       一键启动服务(域名服务、接管进程、代理进程)。
  stop        手动还原系统状态(不包括：内核参数、用户组)。
  update      安全地更新全部的规则配置文件。

Flags:
  -c, --config-dir string   配置文件目录。 (default "/etc/gun")
  -h, --help                help for gun

Use "gun [command] --help" for more information about a command.
```

### 安装必要的系统工具

为了简化，这些步骤已经按系统做好标准化了。

```bash
# 这个命令会检测系统类型和版本，安装必要的系统组件和工具。
$ gun setup
```

但是个人时间和能力有限，无法完整进行覆盖测试。

### 初始化资源文件

程序正常运行需要一些规则文件，比如国内的域名列表、路由段等。
执行下面的命令可以自动从公开资源获取并保存到本地。

```bash
$ gun update
```

鸡生蛋、蛋生鸡问题：`update`命令会从GitHub网站上面下载资源，如果GitHub无法访问……

### 编写配置文件

配置文件非常简单，绝大部分配置默认，只需要配置一下出口参数即可。

```yaml
$ cat /etc/gun/gun.yaml
outputs:
  current: blog
  stocks:
    blog:
      http2socks:
        server: https://...
        token: ...
```

### 启动主程序命令

用 `start` 启动命令时，会自动配置好所需的一切配置：

1. 内核参数
2. 防火墙表、链和规则
3. 黑白路由名单 ipset
4. 系统路由接管
5. DNS请求接管
6. TCP/UDP接管

### 停止

直接结束主进程即可，会尽量把系统恢复到原始状态。

也可以随意执行 `gun stop` 命令，会结束掉所有相关进程。

### OpenWRT

如果是想在OpenWRT上开机自动运行，可以把下面的语句添加到 System ➡️ Startup ➡️ Local Startup 中：

```bash
gun start < /dev/null > /dev/null 2>&1 &
```

日志已自动转发到 system log 中，可以用 `logread` 命令查看。

## 支持的出口协议

* direct
* http2socks
* Trojan
* SSH
* SOCKS5
* NaiveProxy
* Hysteria 2

`direct`是直连协议，将`current`设置为`direct`时使用；
`http2socks`、`trojan`、`ssh`、`socks5`直接内部实现，不依赖外部程序；
`naive`和`hysteria`需要依赖外部二进制文件（需要自行下载，但不需要配置文件）。

## 支持的入口协议

* tproxy

是的，仅这一个。
所有的流量均是由 tproxy 转发到其它出口上的（如果出口协议本身支持tproxy，则不需要转发）。

## DNS 域名服务器（转发器）

域名服务器是我手动实现的一个内存内服务器，用于分流，所有数据缓存在内存中。

支持的功能：

* 域名分流解析（DoT）：常规域名直接解析，不可访问域名走代理后的TCP解析；
* 未知域名（不在任何列表内的域名）走检测逻辑：若国内可解析且结果属国内路由段，走国内分流；
* 解析结果自动添加到ipset，以通过iptables match set实现分流；
* 支持域名屏蔽功能（不允许访问指定列表内的域名）；
* 内存内缓存（最小TTL为5分钟）；

其运行的时候依赖几个主要配置文件全部位于 `/etc/gun` 下，看文件名或者其内的注释可以了解其用途。

如果主机本身有DNS服务器（比如OpenWRT），则会直接以此DNS为默认的国内域名解析器，加快解析速度。

## 配置

配置文件路径：`/etc/gun/gun.yaml`，格式为YAML。

```yaml
dns:
  # DNS转发器的上游服务器。
  # 格式：a.b.c.d 或 a.b.c.d:53
  upstreams:
    # 中国域名解析上游。
    # 可以为空。如果为空：如果有进程监听53号端口，则使用此上游。
    # 否则使用 223.5.5.5。
    china: 223.5.5.5
    # 国外域名解析上游。
    # 可以为空。如果为空，使用 8.8.8.8。
    banned: 8.8.8.8

# 流量出口配置。
outputs:
  # 所有的库存出口列表。
  # 格式为：自定义名字 -> 协议配置。
  # 见后面的“配置”一节。
  stocks:
    name1:
      http2socks:
        key1: value1
    name2:
      hysteria:
        server: addr:port
  # 当前使用的名字，来源于库存列表。
  # 特殊值：direct，使用直连。
  current: string
```

### http2socks

```yaml
# 服务器地址。
# 形如：https://example.com/path/。
server: string
# 客户端与服务端之间的预共享密钥。
token: string
```

### SOCKS5

```yaml
# 服务器地址。
# 形如：example.com:1080
server: string
```

暂未支持设置密码。

### SSH

```yaml
# 服务器地址。
# 形如：example.com:22。
server: string
# 用户名。
username: string
# 密码。
password: string
```

暂时只支持用户名密码认证，后续有需求再添加公钥认证。

### Trojan

只支持标准原生的Trojan协议。

```yaml
# 服务器地址。
# 形如：example.com:443
server: string
# 密码。
password: string
# 是否允许不安全。
insecure_skip_verify: bool
# 指定的服务器SNI名。
sni: string
```

### Naive Proxy

```yaml
# 原 --proxy 参数的值，不包含认证信息。
server: string
# 用户名。
username: string
# 密码。
password: string
# 二进制文件路径。
# 默认为：配置目录/naive。
bin: string
```

### Hysteria 2

为安全起见，目前仅允许持有有效证书的服务器配置。

```yaml
# 服务器地址和端口。
# 形如：example.com:443
server: string
# 密码。形如：password 或 username:password。
password: string
# 二进制文件路径。
# 默认为：配置目录/hysteria。
bin: string
```

## License

MIT.
