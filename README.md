# AnyLink 一键安装脚本

> 适用系统：**Debian 12/Ubuntu 22.04 或更高版本**（amd64/arm64）

一键完成 **证书申请→ 下载并部署 AnyLink → 自动写配置 → 安装 systemd 服务 → 启动与校验** 的全流程；并内置：

* 检测是否已安装 AnyLink，**交互确认后可彻底卸载**
* **先证书，后安装**（证书校验通过才继续）
* **自动释放端口 80/443/8800**（停止常见进程，必要时强杀）
* 自动安装 **iptables**（兼容 AnyLink 的 NAT 初始化）
* 自动探测出口网卡并写入 `ipv4_master`
* 自动修改 `profile.xml` 的 `<HostAddress>` → `域名:443`
* 启动失败自动打印 `journalctl` 最近日志，便于定位

---

## 获取脚本与执行

```bash
wget -O anylink-install.sh https://raw.githubusercontent.com/forjustice/anylink-install/main/anylink-install.sh && chmod +x anylink-install.sh && bash anylink-install.sh

```

> 需要更详细的执行轨迹（调试）：
> `DEBUG=1 bash anylink-install.sh`

---

## 安装流程（脚本内置步骤）

**0. 前置检查**

* 检查/安装依赖：`curl`, `wget`, `tar`, `systemd`, `sed`, `gawk`, `openssl`, `iproute2(ss)`, **`iptables`**
* 检测是否已安装 AnyLink → **询问是否卸载**（选择 `y` 后停止服务、禁用自启、移除 unit 与目录）
* **强制释放端口 80/443/8800**：尝试 `systemctl stop` 常见服务（nginx/apache2/caddy/haproxy/docker-proxy/anylink），仍占用则 `kill -TERM`→`kill -KILL`
* 开启 `net.ipv4.ip_forward=1`；若缺 TUN 设备，给出提示

**1. 申请与校验证书（必须成功才继续）**

* 仅一次读取域名（用于 443/8800）：`acme.example.com`
* 调用 **domainSSL** 脚本自动签发
* 证书固定路径：`/home/ssl/<域名>/1.pem` 与 `/home/ssl/<域名>/1.key`
* 使用 `openssl x509` 校验证书有效性（subject/issuer/有效期）

**2–3. 下载 & 解压 AnyLink**

* 自动获取 **GitHub Releases 最新版本**与架构（`linux-amd64`/`linux-arm64`）
* 解压至 `/usr/local/anylink-deploy/`

**4–5. 生成密文与 JWT**

* `./anylink tool -p freedom123` 生成 **bcrypt** 管理员密码密文（仅显示脱敏片段）
* `./anylink tool -s` 生成 **jwt\_secret**（仅显示脱敏片段）

**6–8. 写配置**

* 基于 `server-sample.toml` 生成 `server.toml`
* 写入：

  * `cert_file = "/home/ssl/<域名>/1.pem"`
  * `cert_key  = "/home/ssl/<域名>/1.key"`
  * `admin_pass = "<bcrypt-hash>"`
  * `jwt_secret = "<secret>"`
  * `ipv4_master = "<自动探测的出口网卡>"`（优先默认路由接口）
* 修改 `conf/profile.xml`：
  将

  ```xml
  <HostEntry>
      <HostName>VPN</HostName>
      <HostAddress>localhost</HostAddress>
  </HostEntry>
  ```

  改为

  ```xml
  <HostEntry>
      <HostName>VPN</HostName>
      <HostAddress><域名>:443</HostAddress>
  </HostEntry>
  ```

  （修改前自动备份为 `profile.xml.bak.<时间戳>`）

**9. 安装 systemd**

* 安装/启用 unit：`anylink.service`
* 为 `[Service]` 注入 `Environment=PATH=/usr/sbin:/usr/bin:/sbin:/bin`（防止 PATH 不含 `/usr/sbin`）

**10. 启动与校验**

* 启动 `anylink`，若失败：自动输出最近 200 行 `journalctl -u anylink` 日志
* 打印常见问题提示 + 前台调试命令

**11. 安装完成输出**

* 管理后台：`https://<域名>:8800`
* 账号：`admin`
* 密码：`freedom123`（明文仅用于初次登录，建议登录后修改）

---

## 注意事项

* **域名解析**需提前生效并指向本机公网 IP；80/443 端口必须可用（脚本会尝试释放占用）。
* 证书路径**固定**为 `/home/ssl/<域名>/1.pem` 与 `/home/ssl/<域名>/1.key`。
* 若你不希望脚本强杀占用进程，可先手动释放端口后再执行脚本。
* 本脚本仅适配 **Debian 12+**，其它发行版可能存在依赖名差异。

---

## 常用命令

```bash
# 查看服务状态（失败时看日志尾部）
sudo systemctl status anylink --no-pager
sudo journalctl -u anylink -n 200 --no-pager

# 重启服务
sudo systemctl restart anylink

# 前台调试（直接查看报错）
/usr/local/anylink-deploy/anylink --conf=/usr/local/anylink-deploy/conf/server.toml
```

---

## 卸载

脚本会**自动检测已安装**并询问是否卸载。若你单独想卸载，可手动执行：

```bash
sudo systemctl stop anylink
sudo systemctl disable anylink
sudo rm -f /etc/systemd/system/anylink.service /usr/lib/systemd/system/anylink.service /lib/systemd/system/anylink.service
sudo systemctl daemon-reload
sudo systemctl reset-failed
sudo rm -rf /usr/local/anylink-deploy
```

> 如需“更彻底”清理，可同时删除日志/数据目录（视你是否保留）：
> `sudo rm -rf /var/log/anylink /var/lib/anylink`

---

## 排错指引（快速）

* **`exec: "iptables" not found`**
  `sudo apt-get install -y iptables`，并确认 unit 已注入 PATH；重启服务。
* **`/dev/net/tun` 不存在**
  `sudo modprobe tun && echo tun | sudo tee /etc/modules-load.d/tun.conf`
* **证书相关错误**
  确认 `/home/ssl/<域名>/1.pem` 与 `1.key` 存在且权限可读；必要时重新签发。
* **端口占用**
  脚本已尝试释放，仍占用时：`sudo ss -ltnp | grep ':80\|:443\|:8800'` 手动排查。
* **网卡名不正确**
  `ip -4 route show default` 查看默认出口；编辑 `server.toml` 的 `ipv4_master` 为正确的接口名，重启服务。

---

## 目录与文件

```
/usr/local/anylink-deploy/
├── anylink                         # 主程序
├── conf/
│   ├── server.toml                 # 主配置（脚本已自动写入）
│   ├── profile.xml                 # 客户端配置（已替换 HostAddress=域名:443）
│   └── server-sample.toml          # 样例模板
└── deploy/ 或 systemd/anylink.service   # unit 模板（脚本会复制到 /etc/systemd/system）
```

证书默认在：`/home/ssl/<域名>/1.pem`、`/home/ssl/<域名>/1.key`

---

## 许可证

Apache-2.0 license
