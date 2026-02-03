package configs

import (
	"log"
	"os"

	"github.com/goccy/go-yaml"
)

const DefaultConfigFileName = `gun.yaml`

type Config struct {
	Outputs OutputsConfig `yaml:"outputs"`
}

type OutputsConfig struct {
	// 所有库存的出口列表。
	// map的key表示此output的名字。
	Stocks YamlMapSlice[string, OutputConfig] `yaml:"stocks"`

	// 订阅的配置(URL）。
	Subscriptions YamlMapSlice[string, string] `yaml:"subscriptions"`

	// 当前使用哪个配置名？
	Current string `yaml:"current"`
}

// 单个的配置。
type OutputConfig struct {
	// 哪个不为空就用哪个。
	HTTP2Socks *HTTP2SocksOutputConfig `yaml:"http2socks,omitempty"`
	Socks5     *Socks5OutputConfig     `yaml:"socks5,omitempty"`
	SSH        *SSHOutputConfig        `yaml:"ssh,omitempty"`
	Trojan     *TrojanOutputConfig     `yaml:"trojan,omitempty"`
}

type HTTP2SocksOutputConfig struct {
	// 服务器地址。
	// 形如：https://example.com/path/。
	Server string `yaml:"server"`
	// 客户端与服务端之间的预共享密钥。
	Token string `yaml:"token"`
}

type Socks5OutputConfig struct {
	// 服务器地址。
	// 形如：example.com:1080
	Server string `yaml:"server"`
}

type SSHOutputConfig struct {
	// 服务器地址。
	// 形如：example.com:22。
	Server string `yaml:"server"`
	// 用户名。
	Username string `yaml:"username"`
	// 密码。
	Password string `yaml:"password"`
}

type TrojanOutputConfig struct {
	// 服务器地址。
	// 形如：example.com:443
	Server string `yaml:"server"`
	// 密码。
	Password string `yaml:"password"`
	// 是否允许不安全。
	InsecureSkipVerify bool `yaml:"insecure_skip_verify"`
	// 指定的服务器SNI名。
	SNI string `yaml:"sni"`
}

type SubscriptionOutputConfig struct {
	URL string `yaml:"url"`
}

func LoadConfigFromFile(path string) *Config {
	fp, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			log.Fatalf(`没有找到配置文件：%s`, path)
		}
		log.Panicf(`读取配置文件时出错：%v`, err)
	}

	defer fp.Close()

	var config Config
	decoder := yaml.NewDecoder(fp, yaml.DisallowUnknownField())
	if err := decoder.Decode(&config); err != nil {
		panic(err)
	}

	return &config
}

type YamlMapSlice[Key comparable, Value any] []YamlMapItem[Key, Value]

type YamlMapItem[Key comparable, Value any] struct {
	Key   Key
	Value Value
}

func (c YamlMapSlice[Key, Value]) MarshalYAML() ([]byte, error) {
	m := yaml.MapSlice{}
	for _, item := range c {
		m = append(m, yaml.MapItem{
			Key:   item.Key,
			Value: item.Value,
		})
	}
	return yaml.Marshal(m)
}

func (c *YamlMapSlice[Key, Value]) UnmarshalYAML(data []byte) error {
	ordered := yaml.MapSlice{}
	if err := yaml.Unmarshal(data, &ordered); err != nil {
		return err
	}

	unordered := map[Key]Value{}
	if err := yaml.Unmarshal(data, &unordered); err != nil {
		return err
	}

	slice := []YamlMapItem[Key, Value]{}

	for _, item := range ordered {
		slice = append(slice, YamlMapItem[Key, Value]{
			Key:   item.Key.(Key),
			Value: unordered[item.Key.(Key)],
		})
	}

	*c = slice

	return nil
}
