# trojan

官方标准版本的 Trojan 协议。此标准不支持 mux。

## 协议

[The Trojan Protocol | trojan](https://trojan-gfw.github.io/trojan/protocol.html)

这个协议官方实现得有点粗糙：

1. 明明是个二进制协议，非要把 sha224 转换成 hex，结果大小翻倍。
2. 明明是个二进制协议，非要写 '\r\n'。应该不写，或者只有 '\n' 就足够。
