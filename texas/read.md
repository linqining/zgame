# texas 部署文档

## 交叉编译（macOS → Linux x86_64）

### 前置条件

```bash
# 1. 安装 zig（交叉编译链接器）
brew install zig

# 2. 安装 cargo-zigbuild
pip3 install cargo-zigbuild
# 或
cargo install cargo-zigbuild

# 3. 添加目标 triple
rustup target add x86_64-unknown-linux-musl
```

### 编译命令

```bash
cd texas
cargo zigbuild --release --target x86_64-unknown-linux-musl
```

### 产物路径

```
target/x86_64-unknown-linux-musl/release/texas
```

产物为 **静态链接** 的 ELF 可执行文件，可直接在 Linux x86_64 环境运行。

### 注意事项

1. **TLS 后端**：`reqwest` 和 `tokio-tungstenite` 使用 `rustls-tls` 而非 `native-tls`，避免交叉编译时 OpenSSL C 依赖的问题。
2. **sui-sdk**：未启用 `vendored-openssl` feature（该 feature 在 SDK v1.73.0 中已不存在）。
3. 编译产物约 19MB，已 strip 调试符号。

---

## 生产部署（AWS EC2 Linux）

### systemd 服务（推荐方案）

systemd 是 AWS Linux 原生自带的进程管理器，零额外依赖，支持自动重启、开机自启、资源限制和 journalctl 日志。

#### 1. 部署二进制

```bash
# 将编译产物上传到服务器
scp target/x86_64-unknown-linux-musl/release/texas ec2-user@<host>:/home/ec2-user/texas/target/release/texas
```

#### 2. 创建 systemd 服务单元文件

`/etc/systemd/system/texas.service`：

```ini
[Unit]
Description=Sui Relayer Texas
After=network.target

[Service]
Type=simple
User=ec2-user
WorkingDirectory=/home/ec2-user/texas
ExecStart=/home/ec2-user/texas/target/release/texas
Restart=always
RestartSec=5
Environment="RUST_LOG=info"

[Install]
WantedBy=multi-user.target
```

#### 3. 启动服务

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now texas
```

#### 4. 查看日志

```bash
sudo journalctl -u texas -f
```

#### 5. 其他常用命令

```bash
sudo systemctl status texas   # 查看状态
sudo systemctl restart texas  # 重启
sudo systemctl stop texas     # 停止
```

---

## 其他进程管理方案参考

### PM2（开发调试友好）

```bash
npm install -g pm2
pm2 start /home/ec2-user/texas/target/release/texas --name texas
pm2 startup    # 生成开机自启脚本
pm2 save
pm2 logs texas
```

CLI 友好、自带日志/监控面板，但依赖 Node.js 运行时。

### 其他轻量选项

| 工具 | 特点 | 适用场景 |
|------|------|----------|
| runit / s6 | 极简 C 实现、快启动、daemontools 风格 | 容器基础镜像 / 嵌入式 |
| Circus | Python 实现，支持 WebSocket 控制台 | Python 生态老项目 |
| Monit | 监控+自愈（CPU/内存超阈值重启） | 配合 systemd 做二级看护 |

### 选型建议

| 场景 | 推荐方案 |
|------|----------|
| **AWS EC2 Linux 生产跑 Rust 二进制** | **systemd（最佳）** |
| 开发调试 / Node.js 前后端同机 | PM2 |
| Docker 容器内 PID 1 | tini 或直接用 CMD |
