# Linkform

一个纯前端的 Clash Meta 代理项转换器。直接用浏览器打开 `index.html`，每行粘贴一个或多条：

- `vless://`（Reality / Vision、TCP、WS、gRPC）
- `hysteria2://` 或 `hy2://`（端口跳跃、salamander / gecko 混淆、证书指纹与 ECH）
- `ss://`（`2022-blake3-aes-256-gcm`，支持 SIP002 Base64 或明文认证信息）

即可获得可复制或下载的 Clash Meta 代理项单行配置。转换成功后，结果会自动复制到剪贴板；每个代理项使用 Mihomo 支持的单行 JSON（YAML 流式对象）格式。

对于 `security=reality` 的 VLESS 节点，转换结果会自动在 `reality-opts` 中加入：

```yaml
support-x25519mlkem768: true
```

用于适配新版 Xray/3x-ui Reality 握手要求（例如 3x-ui 3.8.0 / Xray 26.9.9）。普通 TLS VLESS 与 Hysteria2 节点不会添加该字段。

链接不会发送到任何服务端。

## HY2 转换

支持官方多端口地址，例如：

```text
hy2://user:pa%2Bss@example.com:443,20000-30000/?sni=example.com#HY2
```

端口范围和列表转换为 Mihomo 的 `ports`；完整认证信息保留为 `password: "user:pa+ss"`。IPv6 地址请使用 `[2001:db8::1]` 格式，输出的 `server` 会去掉方括号。

- `pinSHA256` 转换为 `fingerprint`，接受 64 位十六进制 SHA-256 指纹或冒号分隔形式。
- `ech` 转换为 `ech-opts: {enable: true, config: "..."}`。
- 兼容第三方扩展 `mport` / `ports` 和 `hop-interval` / `hopInterval`。间隔单位为秒，支持 `15` 或 `15-30`；省略时使用 Mihomo 默认的 30 秒。官方普通 HY2 URI 不包含跳跃间隔参数。
- `gecko` 支持扩展参数 `obfs-min-packet-size`、`obfs-max-packet-size`。需使用支持 gecko 的 Mihomo 版本。
- 不支持的混淆、无效端口或冲突的跳跃配置会报错；`hysteria2+realm://` 和 `hysteria2+realm+http://` 会明确提示暂不支持。

输出是带 YAML 列表前缀的严格单行 JSON 对象，可放在完整 Mihomo 配置的 `proxies` 下；下载内容仅包含代理项，并非完整配置文件。

## 本地开发与验证

无需安装应用依赖或构建：

```sh
python3 -m http.server 8000 --bind 127.0.0.1
node --test tests/conversion.test.cjs
```

测试使用 Node.js 内置测试工具，覆盖 HY2 端口跳跃、认证解码、TLS 参数、错误输入和 VLESS / SS 转换回归。
