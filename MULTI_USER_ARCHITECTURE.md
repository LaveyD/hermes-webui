# Hermes Web UI: Multi-User Authentication, Workspace Isolation & Access Control

> 本文档描述 Hermes Web UI 多用户模式下的身份认证、工作区隔离、权限控制的整体架构设计
> 和数据流。
>
> 设计原则：管理面与用户面分离，最小权限原则，数据零信任校验。

---

## 1. 系统架构总览

```
┌─────────────────────────────────────────────────────────────────────┐
│                        管理面 (Admin Plane)                         │
│                                                                     │
│  admin_server.py (端口 8790)                                        │
│  ┌───────────────────────────────────────────────┐                  │
│  │  Admin Web UI (内嵌 HTML/CSS/JS)              │                  │
│  │  - 管理员登录                                  │                  │
│  │  - 用户 Dashboard (统计/搜索)                  │                  │
│  │  - 用户 CRUD: 创建/编辑/删除                   │                  │
│  │  - 密码修改 / Workspace 分配                   │                  │
│  └───────────────────┬───────────────────────────┘                  │
│                      │ 读/写                                         │
├──────────────────────┼───────────────────────────────────────────────┤
│                      │                                               │
│  数据层              │  用户面 (WebUI Plane)                          │
│  ┌───────────────────┴──┐   ┌────────────────────────────────┐      │
│  │ .webui_state/        │   │  server.py (端口 8787)          │      │
│  │   users.json         │   │  ┌──────────────────────────┐  │      │
│  │   .sessions.json     │   │  │ api/routes.py (路由)      │  │      │
│  │   webui_users.json   │   │  │  ├─ auth middleware       │  │      │
│  │   .login_attempts    │   │  │  ├─ access_check 拦截     │  │      │
│  │   .signing_key       │   │  │  └─ session/workspace     │  │      │
│  └──────────────────────┘   │  └───────────┬──────────────┘  │      │
│                             │              │                  │      │
│  config.yaml  (webui_users) │   ┌──────────┴──────────────┐  │      │
│  与 users.json 双向同步      │   │ api/ 模块层              │  │      │
│                             │   │  auth.py   - 认证核心    │  │      │
│                             │   │  access_check.py - 权限  │  │      │
│                             │   │  workspace.py  - WS安全  │  │      │
│                             │   │  profiles.py   - Profile │  │      │
│                             │   │  config.py    - 配置     │  │      │
│                             │   └─────────────────────────┘  │      │
│                             └────────────────────────────────┘      │
└─────────────────────────────────────────────────────────────────────┘
```

### 核心设计理念

1. **管理面与用户面物理分离** — `admin_server.py`（管理员）与 `server.py`（用户）是独立进程，不同端口
2. **数据共享** — 通过 `.webui_state/users.json` + `config.yaml` 双向同步实现数据一致
3. **零信任校验** — 每次请求都验证 session、workspace 白名单、session 归属
4. **Profile 即隔离单元** — 用户 -> Profile -> 独立 memory/sessions/skills/cron

---

## 2. 两种运行模式

### 2.1 单密码模式 (Single-Password Mode)

- 通过 `HERMES_WEBUI_PASSWORD` 环境变量或 `settings.json` 的 `password_hash` 配置
- 所有用户共享同一个密码和同一个 Profile
- 无 workspace 限制、无 session 隔离

### 2.2 多用户模式 (Multi-User Mode)

- 通过 `config.yaml` 的 `webui_users` 列表配置
- 每个用户独立：
  - 用户名 + 密码
  - Profile（绑定到 `~/.hermes/profiles/<name>/`）
  - Workspace 白名单
- 自动启用：
  - Session 归属检查
  - Workspace 访问控制
  - 终端封锁
  - Profile 切换封锁

模式切换由 `is_multi_user_mode()` 决定：

```python
def is_multi_user_mode() -> bool:
    """True if config.yaml defines webui_users with at least one entry."""
    return len(load_webui_users()) > 0
```

---

## 3. 数据模型

### 3.1 用户数据 (users.json)

```json
{
  "users": [
    {
      "username": "alice",
      "password_hash": "7eaccfe946842576711850333bb129d71a...",
      "profile": "alice",
      "workspaces": ["/data/project/workspace_alice"],
      "created_at": "2026-05-14T05:41:21.513980+00:00"
    }
  ]
}
```

### 3.2 Session 数据 (.sessions.json)

旧格式（单密码模式）：
```
"token_hex" -> 1747519200.0   (过期时间戳)
```

新格式（多用户模式）：
```
"token_hex" -> {
  "exp": 1747519200.0,
  "username": "alice",
  "profile": "alice",
  "workspaces": ["/data/project/workspace_alice"]
}
```

### 3.3 config.yaml webui_users

```yaml
webui_users:
  - username: alice
    password_hash: 7eaccfe946842576711850333bb129d71a...
    profile: alice
    workspace: /data/project/workspace_alice
  - username: bob
    password_hash: 1fed1aedc685175fa57c644ce50ade428601e7...
    profile: bob
    workspace: /data/project/workspace_bob
```

### 3.4 数据流

```
admin_server.py                          server.py (api/config.py)
─────────────                          ─────────────────────────
  create_user() ──write──> users.json     load_webui_users()
  delete_user() ──write──> users.json     ←read── users.json
  change_password() ──write──> users.json
  update_workspaces() ──write──> users.json
                                      ↓
  _update_config_yaml() ──write──> config.yaml (webui_users)
                                  (双向同步)
```

---

## 4. 认证子系统 (api/auth.py)

### 4.1 密码哈希

```
PBKDF2-HMAC-SHA256
├─ 迭代次数: 600,000 (OWASP 推荐)
├─ Salt: .signing_key (32 字节随机密钥，持久化)
└─ 额外盐: username (防止同密码用户的 hash 碰撞)

hash = PBKDF2("username:password", signing_key, 600000)
```

### 4.2 Session 管理

```
create_session_with_user_info(username, profile, workspaces)
  ├─ 生成 32 字节随机 token
  ├─ 用 signing_key 签名: HMAC-SHA256(token)[:32]
  ├─ 存储到 .sessions.json (带用户元数据)
  └─ 返回 "token.signature" 格式 Cookie

verify_session("token.signature")
  ├─ 验证 HMAC 签名 (时序安全比较)
  ├─ 检查过期时间
  ├─ 惰性清理所有过期 session (_prune_expired_sessions)
  └─ 返回 True/False
```

### 4.3 登录流程

```
客户端                          服务端 (routes.py / api/auth.py)
───                            ─────────────────────────────────
1. POST /api/auth/login
   { username, password }     2. is_auth_enabled()? → 401 或继续
                              3. IP 频率检查 (5次/60秒)
                              4. is_multi_user_mode()?
                              ├─ 是 → verify_multi_user_login()
                              │         ├─ find_user(username)
                              │         ├─ hash 比较 (或明文+升级)
                              │         └─ create_session_with_user_info()
                              │            → Set-Cookie: hermes_session=...
                              │            → Set-Cookie: hermes_profile=...
                              └─ 否 → verify_password()
                                        → create_session()
                                           → Set-Cookie: hermes_session=...
5. 返回 { ok: true, profile, workspace }
```

### 4.4 安全防护

| 防护措施 | 实现位置 | 说明 |
|---------|---------|------|
| 密码哈希 | `_hash_user_password()` | PBKDF2 60万迭代 + signing_key salt |
| 用户名盐 | `f'{username}:{password}'` | 防止同密码 hash 碰撞 |
| 签名 Cookie | `token.hmac_signature` | 防 Cookie 伪造 |
| 时序安全比较 | `hmac.compare_digest()` | 防时序攻击 |
| 登录频率限制 | `_check_login_rate()` | IP 级别 5次/60秒 |
| Session 过期惰性清理 | `_prune_expired_sessions()` | 每次验证时清理 |
| 原子写入 | `tempfile + os.replace()` | 防崩溃导致数据损坏 |
| Open Redirect 防护 | `login.js _safeNextPath()` | 拒绝 `//`, `\`, 绝对 URL, 控制字符 |
| 文件权限 | `chmod 0600` | session/signing_key 仅 owner 可读 |

---

## 5. 权限控制子系统 (api/access_check.py)

### 5.1 架构

```
HTTP 请求
  │
  ├─ api/auth.check_auth()        ← 认证 (Session 验证)
  │     └─ 未通过 → 401 / 302 到 /login
  │
  └─ api/routes.py 路由处理
        │
        ├─ check_workspace_access()  ← Workspace 白名单
        ├─ check_session_ownership()  ← Session 归属
        ├─ block_terminal()           ← 终端封锁
        └─ block_profile_switch()     ← Profile 切换封锁
```

### 5.2 权限检查函数

#### check_workspace_access(handler, workspace_path)

```python
def check_workspace_access(handler, workspace_path: str) -> Path | None:
    """检查 workspace 路径是否在用户允许列表中"""
    user = _get_current_user(handler)
    candidate = Path(workspace_path).expanduser().resolve()
    allowed = [Path(w).expanduser().resolve() for w in user['workspaces']]

    for root in allowed:
        if candidate.relative_to(root):  # 在允许的根目录下
            return candidate  # ✓ 通过

    # ✗ 拒绝
    send_json_response(handler, {'error': 'Workspace access denied'}, 403)
    return None
```

#### check_session_ownership(handler, session_profile)

```python
def check_session_ownership(handler, session_profile: str) -> bool:
    """检查 session 是否属于当前用户"""
    user = _get_current_user(handler)
    if user['profile'] != session_profile:
        send_json_response(handler, {'error': 'Session access denied'}, 403)
        return False
    return True
```

#### block_terminal(handler) / block_profile_switch(handler)

```python
def block_terminal(handler):
    """多用户模式下禁用终端访问"""
    if is_multi_user_mode():
        send_json_response(handler, {'error': 'Terminal disabled in multi-user mode'}, 403)
        return True
    return False
```

### 5.3 权限检查集成到路由

**Session 操作（归属检查）：**

| 端点 | 方法 | 检查 |
|------|------|------|
| `/api/session/rename` | POST | `check_session_ownership` |
| `/api/session/delete` | POST | `check_session_ownership` |
| `/api/session/duplicate` | POST | `check_session_ownership` |
| `/api/session/truncate` | POST | `check_session_ownership` |
| `/api/session/restore` | POST | `check_session_ownership` |
| `/api/session/toolsets` | POST | `check_session_ownership` |
| `/api/sessions/cleanup` | POST | `check_session_ownership` |
| `/api/sessions/cleanup_zero_message` | POST | `check_session_ownership` |

**Workspace 操作（白名单检查）：**

| 端点 | 方法 | 检查 |
|------|------|------|
| `/api/workspace/register` | POST | `check_workspace_access` |
| `/api/workspace/set` | POST | `check_workspace_access` |
| `/api/rollback/restore` | POST | `check_workspace_access` |
| `/api/files` | GET | `check_workspace_access` |

**封锁端点（多用户模式）：**

| 端点 | 方法 | 封锁 |
|------|------|------|
| `/api/terminal/submit` | POST | `block_terminal` |
| `/api/terminal/background` | POST | `block_terminal` |
| `/api/terminal/process/*` | POST | `block_terminal` |
| `/api/terminal/files` | GET | `block_terminal` |
| `/api/profile/switch` | POST | `block_profile_switch` |
| `/api/profiles` | POST | `block_profile_switch` |
| `/api/profiles/*` | DELETE/POST | `block_profile_switch` |

---

## 6. Profile 隔离子系统 (api/profiles.py)

### 6.1 隔离模型

```
用户 "alice"
  └─ Profile "alice"
       └─ HERMES_HOME = ~/.hermes/profiles/alice/
            ├─ memories/      ← 用户记忆
            ├─ sessions/      ← 对话历史
            ├─ skills/        ← AI 技能
            ├─ skins/         ← 主题
            ├─ logs/          ← 日志
            ├─ plans/         ← 计划
            ├─ workspace/     ← 默认工作区
            ├─ cron/          ← 定时任务
            └─ webui_state/   ← WebUI 状态 (workspaces.json, last_workspace.txt)
```

### 6.2 Thread-Local 上下文

```python
# 每个 HTTP 请求线程读取自己的 profile cookie
_tls = threading.local()

# 请求开始时设置
_tls.profile = cookie_profile_name

# 请求处理中使用
get_active_profile_name() → _tls.profile 或 _active_profile

# 请求结束时清理
del _tls.profile
```

这确保了并发请求不会互相污染 profile 上下文（issue #798）。

### 6.3 Profile 切换流程

```
switch_profile(name)
  ├─ 验证 profile 格式 (^[a-z0-9][a-z0-9_-]{0,63}$)
  ├─ 更新 os.environ['HERMES_HOME']
  ├─ 更新 _active_profile (thread-safe)
  ├─ patch_skill_home_modules() ← 修复 import 时缓存的路径
  └─ 重新加载 config.yaml
```

---

## 7. Workspace 安全子系统 (api/workspace.py)

### 7.1 多层防护

```
请求: workspace = "/etc/shadow"
  │
  ├─ 1. 用户白名单 (access_check.py)
  │     ├─ 用户允许: ["/data/workspace_alice"]
  │     └─ ✗ /etc/shadow 不在白名单中 → 403
  │
  ├─ 2. 系统路径黑名单 (workspace.py)
  │     ├─ /etc, /usr, /var, /bin, /sbin, /boot
  │     ├─ /proc, /sys, /dev, /lib, /lib64
  │     ├─ /opt/homebrew, /System, /Library
  │     └─ ✗ /etc 在黑名单中 → 拒绝
  │
  ├─ 3. macOS Symlink 防护
  │     ├─ /etc → /private/etc (解析后检查)
  │     └─ 同时检查原始路径和解析后路径
  │
  ├─ 4. 用户临时目录例外
  │     ├─ /var/folders/*  (macOS per-user tmp)
  │     ├─ /var/tmp, /private/var/tmp
  │     └─ 即使父目录在黑名单，例外仍通过
  │
  └─ 5. 跨 Profile 泄漏防护
        ├─ ~/.hermes/profiles/alice/ → 不允许出现在 bob 的列表中
        └─ 只允许当前 Profile 自己的目录
```

### 7.2 Workspace 存储

每个 Profile 独立存储 workspace 配置：

```
~/.hermes/profiles/alice/webui_state/workspaces.json
~/.hermes/profiles/alice/webui_state/last_workspace.txt

# 默认 Profile 使用全局路径
~/.hermes/webui/workspaces.json          (向后兼容)
~/.hermes/webui/last_workspace.txt
```

### 7.3 Workspace 建议系统

```python
list_workspace_suggestions(prefix, limit=12)
  ├─ 只扫描受信任根目录:
  │     ├─ Path.home()
  │     ├─ 启动时配置的 default workspace
  │     └─ 已保存的 workspace 根目录
  ├─ 不扫描任意系统路径
  └─ 返回空列表而非错误 (前端安全)
```

---

## 8. 管理员面板 (admin_server.py)

### 8.1 架构

```
admin_server.py (独立进程, 端口 8790)
  │
  ├─ HTTP Server (http.server.BaseHTTPRequestHandler)
  │   │
  │   ├─ GET  /                 → 内嵌 HTML/CSS/JS 管理页面
  │   ├─ GET  /api/users        → 用户列表 (脱敏: 无密码)
  │   │
  │   ├─ POST /api/admin/login  → 管理员登录
  │   ├─ POST /api/admin/logout → 管理员登出
  │   │
  │   ├─ POST /api/users/create          → 创建用户 + 自动建 workspace 目录
  │   ├─ POST /api/users/delete          → 删除用户 (不能删除最后一个)
  │   ├─ POST /api/users/change_password → 修改密码
  │   └─ POST /api/users/update_workspaces → 修改 workspace 列表
  │
  └─ 数据同步
       ├─ 读取: users.json → 优先, webui_users.json → 回退
       └─ 写入: users.json ← 主存储
              config.yaml ← 同步 (webui_users 部分)
```

### 8.2 管理员认证

```
ADMIN_PASSWORD 环境变量 (默认 "admin")
  │
  ├─ POST /api/admin/login
  │     { password: "xxx" }
  │     → 生成随机 token (secrets.token_hex(16))
  │     → Set-Cookie: admin_token=<token>; HttpOnly; Max-Age=86400
  │     → 存储到内存: _admin_sessions[token] = timestamp
  │
  └─ 每次请求验证:
       ├─ 检查 admin_token cookie
       ├─ 检查是否过期 (24小时)
       └─ 刷新过期时间
```

### 8.3 管理页面

内嵌单页应用 (无构建步骤)：

- 登录界面 → Dashboard → 用户表格
- 用户搜索/过滤
- 创建用户 Modal: 用户名 + 密码 + Profile + Workspace 列表
- 编辑用户 Modal: 改密码 + 改 Workspace
- 删除用户 Modal: 二次确认
- 统计卡片: 总用户数 / 总 Workspace 数 / State 目录路径

---

## 9. 文件目录结构

```
hermes-webui/
│
├── server.py                     # 主入口 (HTTP Handler, 路由分发)
├── admin_server.py               # 管理员面板 (独立进程)
├── bootstrap.py                  # 一键启动 (安装 + 健康检查 + 浏览器打开)
│
├── api/
│   ├── auth.py                   # 认证核心 (Session, Cookie, 密码哈希)
│   ├── access_check.py           # 权限控制 (Workspace/Session 检查, 封锁)
│   ├── workspace.py              # Workspace 安全 (黑名单, 建议, 存储)
│   ├── profiles.py               # Profile 管理 (隔离, 切换, Thread-Local)
│   ├── config.py                 # 配置管理 (含 webui_users 加载)
│   ├── routes.py                 # 路由处理 (所有端点 + 权限拦截集成)
│   ├── models.py                 # Session 模型
│   ├── helpers.py                # HTTP 工具 (j(), bad(), CSP, 压缩)
│   ├── streaming.py              # SSE 流式传输
│   └── ... (其他模块)
│
├── static/
│   ├── index.html                # SPA 主页面
│   ├── login.js                  # 登录页面脚本 (支持多用户/单密码模式)
│   ├── workspace.js              # Workspace 面板
│   ├── sessions.js               # Session 管理
│   ├── messages.js               # 消息渲染
│   ├── ui.js                     # UI 工具
│   ├── boot.js                   # 启动初始化
│   ├── style.css                 # 样式
│   └── ... (其他静态资源)
│
├── .webui_state/
│   ├── users.json                # 用户数据 (主存储)
│   ├── webui_users.json          # config.yaml 缓存副本
│   ├── .sessions.json            # Session 存储
│   ├── .login_attempts.json      # 登录尝试记录
│   ├── .signing_key              # 签名密钥 (0600)
│   └── settings.json             # 全局设置
│
└── config.yaml                   # 配置文件 (含 webui_users, 与 users.json 双向同步)
```

---

## 10. 请求生命周期 (多用户模式)

```
1. 客户端发起请求 → server.py
2. server.py → Handler → do_GET/do_POST
3. check_auth() → 解析 cookie → verify_session()
   └─ 失败 → 401 (API) / 302 /login (页面)
4. 读取 hermes_profile cookie → 设置 thread-local profile
5. 路由匹配 → routes.py handle_get/handle_post
6. 路由处理:
   ├─ 如果是 session 操作 → check_session_ownership()
   ├─ 如果是 workspace 操作 → check_workspace_access()
   ├─ 如果是终端操作 → block_terminal()
   ├─ 如果是 profile 操作 → block_profile_switch()
   └─ 正常处理请求
7. 返回响应
8. 清理 thread-local profile
```

---

## 11. 安全要点

| 安全威胁 | 防护措施 |
|---------|---------|
| 密码泄露 | PBKDF2-SHA256 60万迭代 + 随机 salt |
| Cookie 伪造 | HMAC-SHA256 签名 + 时序安全比较 |
| Session 劫持 | HttpOnly Cookie + 30天过期 + 惰性清理 |
| 暴力破解 | IP 级别 5次/60秒限制 |
| Workspace 越权 | 白名单检查 (相对路径验证) |
| Session 泄露 | 归属检查 (profile 匹配) |
| 终端滥用 | 多用户模式全局封锁 |
| Profile 切换 | 多用户模式全局封锁 |
| 系统路径访问 | 黑名单 (/etc, /usr, /proc...) |
| macOS Symlink 绕过 | 原始路径 + 解析路径双重检查 |
| 跨 Profile 数据泄漏 | workspace 列表清洗 (移除其他 Profile 路径) |
| Open Redirect | login.js _safeNextPath() 严格验证 |
| CSRF | Origin/Host 头检查 (_check_csrf) |
| 数据损坏 | 原子写入 (tempfile + os.replace) |
| 文件权限 | signing_key/sessions 0600 |
| XSS | CSP 头 (default-src 'self') |
| 点击劫持 | X-Frame-Options: DENY |

---

## 12. 部署配置

### 12.1 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| HERMES_WEBUI_HOST | 127.0.0.1 | 监听地址 |
| HERMES_WEBUI_PORT | 8787 | WebUI 端口 |
| HERMES_WEBUI_PASSWORD | (空) | 单密码模式密码 |
| HERMES_WEBUI_STATE_DIR | ~/.hermes/webui | 状态目录 |
| HERMES_WEBUI_SESSION_TTL | 2592000 | Session 有效期 (秒) |

### 12.2 启动方式

```bash
# WebUI 主服务
python3 server.py

# 管理员面板 (独立启动)
HERMES_WEBUI_STATE_DIR=/path/to/.webui_state \
ADMIN_PASSWORD=your_admin_pw \
python3 admin_server.py --port 8790

# 或者通过启动脚本
./start.sh
```

### 12.3 配置多用户

在 `config.yaml` 中添加：

```yaml
webui_users:
  - username: alice
    password_hash: <pbkdf2-hex>
    profile: alice
    workspace: /data/workspace_alice
```

或通过管理面板创建用户（推荐，自动哈希密码 + 创建目录）。
