# Linkform

一个纯前端的 Clash Meta 代理项转换器。直接用浏览器打开 `index.html`，每行粘贴一个或多条：

- `vless://`（Reality / Vision、TCP、WS、gRPC）
- `hysteria2://` 或 `hy2://`（含 salamander 混淆）
- `ss://`（`2022-blake3-aes-256-gcm`，支持 SIP002 Base64 或明文认证信息）

即可获得可复制或下载的 Clash Meta 代理项单行配置。转换成功后，结果会自动复制到剪贴板；每个代理项使用 Mihomo 支持的单行 JSON（YAML 流式对象）格式。

对于 `security=reality` 的 VLESS 节点，转换结果会自动在 `reality-opts` 中加入：

```yaml
support-x25519mlkem768: true
```

用于适配新版 Xray/3x-ui Reality 握手要求（例如 3x-ui 3.8.0 / Xray 26.9.9）。普通 TLS VLESS 与 Hysteria2 节点不会添加该字段。

链接不会发送到任何服务端。
