# tables

[Iptables Tutorial 1.2.3](https://www.frozentux.net/iptables-tutorial/iptables-tutorial.html)

## 策略路由

```text
process
  ↓
mangle OUTPUT
  ↓
-p tcp --syn → jump ${rule}
  ↓
CONNMARK set 0x486
  ↓
MARK set 0x486
  ↓
ip rule fwmark 0x486
  ↓
policy route
  ↓
mangle PREROUTING
  ↓
connmark 0x486
  ↓
TPROXY
  ↓
127.0.0.1:60080
```
