# 8789/8790 部署说明

> ⚠️ 此服务**完全独立**于 8082 端口的 hermes-webui，**不要混用环境变量或进程**。

---

## 端口与路径

| 端口 | 服务 | 路径 | 说明 |
|------|------|------|------|
| **8789** | hermes-webui | `/data/project/yml/hermes-webui/server.py` | 多用户 WebUI |
| **8790** | admin_server | `/data/project/yml/hermes-webui/admin_server.py` | 用户/Workspace 管理面板 |
| 8082 | 另一个 hermes-webui | `/home/hermes_webui/server.py` | ❌ **与此服务无关** |

## 用户与 Workspace

- 用户数据：`/data/project/yml/hermes-webui/.webui_state/users.json`
- 用户会话：`/data/project/yml/hermes-webui/.webui_state/.user_sessions/`
- Workspace 目录：`/data/project/yml/hermes-webui/workspace_<用户名>/`
- 对话缓存：`/data/project/yml/hermes-webui/.webui_state/sessions/`

---

## 启动命令

### 8789 WebUI（必须显式设置环境变量）

```bash
cd /data/project/yml/hermes-webui
HERMES_WEBUI_PORT=8789 HERMES_WEBUI_STATE_DIR=/data/project/yml/hermes-webui/.webui_state nohup python3 server.py > /tmp/hermes_webui_8789.log 2>&1 &
```

**为什么必须传环境变量？**
因为全局环境变量 `HERMES_WEBUI_PORT=8082`、`HERMES_WEBUI_STATE_DIR=/root/.hermes/webui` 属于 8082 服务。不显式覆盖会继承全局变量，导致：
- 端口冲突（启动到 8082，被占用）
- state_dir 指向错误路径（对话/用户数据读到 8082 的数据）

### 8790 Admin Server（必须使用 YML_AGENT_STATE_DIR）

```bash
cd /data/project/yml/hermes-webui
YML_AGENT_STATE_DIR=/data/project/yml/hermes-webui/.webui_state ADMIN_PASSWORD=admin nohup python3 admin_server.py --port 8790 > /tmp/admin_server.log 2>&1 &
```

**环境变量说明：**
- `YML_AGENT_STATE_DIR` — admin_server.py 专用变量名，**不是** `HERMES_WEBUI_STATE_DIR`
- 已修改为 `YML_AGENT_STATE_DIR` 避免继承 8082 的全局环境变量
- `ADMIN_PASSWORD` — admin 面板密码（默认 `admin`）

---

## 重启流程

### 只重启 8789

```bash
kill $(ss -tlnp | grep ':8789' | grep -v 18789 | grep -oP 'pid=\K[0-9]+')
cd /data/project/yml/hermes-webui
HERMES_WEBUI_PORT=8789 HERMES_WEBUI_STATE_DIR=/data/project/yml/hermes-webui/.webui_state nohup python3 server.py > /tmp/hermes_webui_8789.log 2>&1 &
sleep 2
ss -tlnp | grep ':8789'
```

### 只重启 8790

```bash
kill $(ss -tlnp | grep ':8790' | grep -v 18790 | grep -oP 'pid=\K[0-9]+')
cd /data/project/yml/hermes-webui
YML_AGENT_STATE_DIR=/data/project/yml/hermes-webui/.webui_state ADMIN_PASSWORD=admin nohup python3 admin_server.py --port 8790 > /tmp/admin_server.log 2>&1 &
sleep 2
ss -tlnp | grep ':8790'
```

### 同时重启两个

```bash
kill $(ss -tlnp | grep ':8789' | grep -v 18789 | grep -oP 'pid=\K[0-9]+')
kill $(ss -tlnp | grep ':8790' | grep -v 18790 | grep -oP 'pid=\K[0-9]+')
sleep 1

cd /data/project/yml/hermes-webui

# 启动 8789
HERMES_WEBUI_PORT=8789 HERMES_WEBUI_STATE_DIR=/data/project/yml/hermes-webui/.webui_state nohup python3 server.py > /tmp/hermes_webui_8789.log 2>&1 &

# 启动 8790
YML_AGENT_STATE_DIR=/data/project/yml/hermes-webui/.webui_state ADMIN_PASSWORD=admin nohup python3 admin_server.py --port 8790 > /tmp/admin_server.log 2>&1 &

sleep 2
ss -tlnp | grep -E ':(8789|8790)\b'
```

---

## 常见故障排查

### 8789 启动失败：Address already in use

```
OSError: [Errno 98] Address already in use
```

原因：没有传 `HERMES_WEBUI_PORT=8789`，继承了全局 8082 环境变量。
解决：使用上面的完整启动命令。

### 8790 显示 State Dir = /root/.hermes

原因：没有传 `YML_AGENT_STATE_DIR` 或用了旧变量名 `HERMES_WEBUI_STATE_DIR`。
解决：使用 `YML_AGENT_STATE_DIR=/data/project/yml/hermes-webui/.webui_state` 启动。

### 新用户看到别人的对话缓存

原因：浏览器 localStorage 保留了上一个用户的 session ID。
解决：此问题已通过 `static/login.js` 修改修复，登录时自动清除缓存。重启 8789 生效。

### 新建用户后登录 401

原因：admin_server 写入 `users.json`，但 server.py 从 `config.yaml` 读用户。如果 `config.yaml` 不同步，新用户找不到。
解决：
```bash
# 手动同步（从 users.json → config.yaml）
python3 -c "
import yaml, json
users = json.load(open('/data/project/yml/hermes-webui/.webui_state/users.json'))
cfg = yaml.safe_load(open('/data/project/yml/hermes-webui/.hermes_test/config.yaml')) or {}
cfg['webui_users'] = [{'username':u['username'],'password_hash':u.get('password_hash',''),'profile':u.get('profile',u['username']),'workspace':u['workspaces'][0] if u.get('workspaces') else ''} for u in users['users']]
with open('/data/project/yml/hermes-webui/.hermes_test/config.yaml','w') as f: yaml.dump(cfg,f,default_flow_style=False,allow_unicode=True)
"
# 然后重启 8789（见上方命令）
```
> 此问题已通过修改 `admin_server.py` 的 `_update_config_yaml()` 修复（2026-05-19），新建用户后自动同步。已存在的旧用户需手动同步一次。

---

## 关键文件修改记录

| 文件 | 修改内容 | 原因 |
|------|---------|------|
| `admin_server.py:42` | `YML_AGENT_STATE_DIR` 替代 `HERMES_WEBUI_STATE_DIR` | 避免继承 8082 的全局环境变量 |
| `admin_server.py:334` | `_update_config_yaml()` 硬编码 config.yaml 路径 | 避免写错位置导致新用户登录 401 |
| `static/login.js` | 登录成功后清除 localStorage/sessionStorage | 防止新用户看到旧用户的对话缓存 |
