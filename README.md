# clash-rule

自用规则集合与模板，兼容 Clash.Meta、Stash、Clash Verge、OpenClash 等客户端。

## 通用 DNS 防泄漏模板
- 位置：`templates/dns.yaml`
- 作用：统一 fake-ip + DoH + DNS Hijack，避免系统/ISP DNS 泄漏，确保被代理域名的解析走代理通道。
- 适用：Clash.Meta 内核的客户端（Stash/Clash Verge/OpenClash 等）。

### 使用方法
1. 生成规则文件后，将 `templates/dns.yaml` 中的 `dns` 和 `tun` 段落直接追加到最终配置（`mix`/`meta` 模式均可）。
2. 如果用 subconverter，可在订阅链接后拼接 `&config=https://raw.githubusercontent.com/LUCK777777/clash-rule/refs/heads/main/templates/dns.yaml` 自动合并。
3. Stash：在 Profile 中编辑配置，粘贴 `dns`/`tun` 段；确保「系统 DNS」关闭，启用 Fake-IP。
4. Clash Verge / Meta GUI：在“配置”中打开编辑器，合并 `dns`/`tun` 段并保存；确保内核为 Clash.Meta 并启用 TUN。
5. OpenClash：在“配置文件管理”中编辑当前配置，追加 `dns`/`tun` 段；勾选“Fake-IP 模式”和“防 DNS 泄漏”。

模板关键点：
- `proxy-server-nameserver` 让被代理的域名解析直接走代理隧道（Cloudflare/Google DoH）。
- `dns-hijack: any:53` 将应用发出的 DNS 请求劫持进内核，避免系统直连泄漏。
- `fallback-filter` 以 GEOIP=CN 判断直连/代理，国外域名走代理解析，减少污染。
- `cache-algorithm` + `cache-size` 提升多客户端/脚本场景下的解析性能。

## 规则自动更新 / 镜像工作流
- 位置：`.github/workflows/update.yml`
- 作用：每天 02:00 UTC 定时（或手动 dispatch）拉取 `sources.txt` 中的所有上游规则到 `mirror/`，同时用最新镜像 URL 生成 `dist/custom.ini`。
- 推送：如有变更，自动提交 `mirror/ dist/ MIRROR_UPDATED` 等文件并推送到当前仓库；推送前会先自动 rebase 以消除与主分支的提交冲突。

### 使用/定制
1. 打开 GitHub Actions，允许计划任务运行。
2. 默认使用 `scripts/fetch.py` + `scripts/build.py`：前者把源规则同步到本地镜像，后者将模板中的上游 URL 替换成镜像 URL（默认指向本仓库 `main` 分支下的 `mirror/`）。
3. 如需自定义镜像地址，可在运行时设置环境变量 `MIRROR_PREFIX`，或在 `scripts/build.py` 中调整默认的镜像前缀（支持 gh-pages、自建 CDN 等）。
4. 手动执行：
   ```bash
   pip install requests
   python scripts/fetch.py
   python scripts/build.py
   ```
   完成后可自建推送或触发 Actions 手动运行更新。
