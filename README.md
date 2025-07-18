# Happy Work 后端服务

这是一个AI驱动的职场PUA解决方案后端服务。该系统提供智能化的职场 PUA 场景分析和应对建议，帮助用户更好地处理职场中的不合理要求和不公平对待。

## 功能特点

- 🔐 完整的用户认证系统
  - 邮箱注册和登录
  - 验证码邮件发送与验证
  - JWT令牌身份验证
  - 密码修改功能
- 🤖 智能AI交互功能
  - 基于 DeepSeek 的智能建议生成
  - 两种对话模式：PUA场景模拟和解决方案建议
  - 支持多轮上下文对话
- 💬 聊天管理功能
  - 创建和管理多个聊天会话
  - 完整的聊天历史记录存储
  - 聊天内容持久化存储
- 📊 问卷评估系统
  - 用户职场情况问卷调查
  - 智能分析报告生成
  - 报告预览功能
- 👮‍♂️ 管理员系统
  - 用户管理功能
  - 聊天记录查看和管理
  - 统计数据查询
  - 管理员后台页面
- 🔄 系统维护功能
  - 聊天记录自动清理（可配置保留天数）
  - 数据库迁移工具
  - 完整的日志记录系统
- 🌐 安全与兼容性
  - CORS 跨域支持
  - 敏感信息环境变量配置
  - 静态文件服务支持
  - HTTP/HTTPS 支持
- 💰 付费功能
  - 用户付费状态管理
  - PDF报告生成和存储

## 技术栈

- Python 3.x
- SQLAlchemy (ORM)
- DeepSeek API (AI功能)
- JWT 认证
- SQLite 数据库
- SMTP 邮件服务
- HTTP 服务器
- OpenAI API 接口

## 项目结构

```
backend/
├── server.py                   # 主服务器文件
├── models.py                   # 数据库模型
├── ai_service.py               # AI 服务集成
├── cleanup_chats.py            # 聊天记录清理脚本
├── create_admin.py             # 管理员账户创建脚本
├── requirements.txt            # 项目依赖
├── .env                        # 环境变量配置
├── .env.example                # 环境变量示例配置
├── templates/                  # 模板文件
│   ├── admin.html              # 管理员界面
│   ├── email_verification.html # 邮箱验证模板
│   └── preview_report.html     # 报告预览模板
├── users.db                    # 生产环境 SQLite 数据库文件
└── dev_users.db                # 开发环境 SQLite 数据库文件
```

## 环境要求

- Python 3.x
- 所有依赖包（见 requirements.txt）
- DeepSeek API 密钥
- 邮件服务器配置

## 安装步骤

1. 克隆项目到本地
2. 创建并激活虚拟环境（推荐）：
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   # 或
   .\venv\Scripts\activate  # Windows
   ```
3. 安装依赖：
   ```bash
   pip install -r requirements.txt
   ```
4. 配置环境变量：
   - 复制 `.env.example` 为 `.env`
   - 填写必要的环境变量（API密钥、邮件配置等）

## 运行服务

```bash
python server.py
```

服务器将在 http://localhost:8000 上启动（或根据 .env 中的 PORT 配置）

## API 接口文档

### 认证相关

#### 发送验证码
- **POST** `/send_code`
- 请求体：
  ```json
  {
    "email": "user@example.com"
  }
  ```

#### 验证码登录
- **POST** `/verify_code`
- 请求体：
  ```json
  {
    "email": "user@example.com",
    "code": "123456"
  }
  ```

#### 用户注册
- **POST** `/register`
- 请求体：
  ```json
  {
    "email": "user@example.com",
    "password": "password123"
  }
  ```

#### 用户登录
- **POST** `/login`
- 请求体：
  ```json
  {
    "email": "user@example.com",
    "password": "password123"
  }
  ```

### 聊天相关

#### 发送消息
- **POST** `/chat/message`
- 请求头：需要 JWT Token
- 请求体：
  ```json
  {
    "message": "用户消息",
    "chatId": "会话ID",
    "mode": "simulation" // 或 "solution"
  }
  ```

#### 初次提交场景信息
- **POST** `/chat/message`
- 请求头：需要 JWT Token
- 请求体：
  ```json
  {
    "puaType": ["加班PUA", "绩效PUA"],
    "severity": "严重",
    "perpetrator": ["直属领导"],
    "description": "详细描述...",
    "mode": "simulation" // 或 "solution"
  }
  ```

#### 获取所有聊天会话
- **GET** `/chat/history`
- 请求头：需要 JWT Token

#### 获取单个聊天历史
- **GET** `/chat/{chatId}`
- 请求头：需要 JWT Token

### 问卷相关

#### 提交问卷
- **POST** `/questionnaire/submit`
- 请求头：需要 JWT Token
- 请求体：
  ```json
  {
    "answers": {...} // 问卷答案数据
  }
  ```

#### 获取用户问卷
- **GET** `/questionnaire/list`
- 请求头：需要 JWT Token

#### 预览问卷报告
- **GET** `/preview/{previewId}`
- 可直接在浏览器访问

### 用户相关

#### 获取用户信息
- **GET** `/user/info`
- 请求头：需要 JWT Token

#### 修改密码
- **POST** `/change_password`
- 请求头：需要 JWT Token
- 请求体：
  ```json
  {
    "oldPassword": "旧密码",
    "newPassword": "新密码"
  }
  ```

### 管理员功能

#### 获取所有用户
- **GET** `/admin/users`
- 请求头：需要管理员 JWT Token

#### 获取所有聊天记录
- **GET** `/admin/chats`
- 请求头：需要管理员 JWT Token

#### 获取系统统计信息
- **GET** `/admin/stats`
- 请求头：需要管理员 JWT Token

#### 获取特定聊天记录详情
- **GET** `/admin/chat_details?chat_id={chatId}`
- 请求头：需要管理员 JWT Token

#### 删除特定聊天记录
- **GET** `/admin/delete_chat?chat_id={chatId}`
- 请求头：需要管理员 JWT Token

#### 清空所有聊天记录
- **GET** `/admin/clear_all_chats`
- 请求头：需要管理员 JWT Token

#### 删除用户
- **POST** `/admin/delete_user`
- 请求头：需要管理员 JWT Token
- 请求体：
  ```json
  {
    "userId": "要删除的用户ID"
  }
  ```

#### 管理员界面
- **GET** `/admin`
- 请求头：需要管理员 JWT Token

## 环境变量配置

在 `.env` 文件中配置以下变量：

```
# API密钥
DEEPSEEK_API_KEY=你的DeepSeek API密钥
JWT_SECRET=JWT密钥

# 邮件配置
EMAIL_FROM=发件人邮箱
EMAIL_USER=邮箱用户名
EMAIL_PASSWORD=邮箱密码
SMTP_SERVER=邮件服务器地址
SMTP_PORT=邮件服务器端口

# CORS配置
ALLOWED_ORIGINS=允许的域名列表，用逗号分隔

# 服务器配置
PORT=服务器端口号

# 聊天记录自动清理配置
ENABLE_CHAT_CLEANUP=true        # 设置为false可禁用自动清理
CHAT_RETENTION_DAYS=30          # 聊天记录保留天数
CHAT_CLEANUP_INTERVAL_HOURS=24  # 清理任务执行间隔(小时)

# 数据库配置
# FLASK_ENV=development         # 取消注释并设置为development以使用开发环境数据库(dev_users.db)
```

## 管理员创建工具

使用以下命令创建管理员账户：

```bash
python create_admin.py --email admin@example.com --password admin密码
```

## 开发和维护工具

- `create_admin.py`: 创建管理员用户
  ```bash
  python create_admin.py --email admin@example.com --password admin密码
  ```

- `cleanup_chats.py`: 手动清理过期聊天记录
  ```bash
  python cleanup_chats.py
  ```

## 注意事项

1. 确保 DeepSeek API 密钥配置正确
2. 邮件服务器配置需要正确设置，否则验证码功能不可用
3. 生产环境部署时请修改 CORS 和 JWT 设置
4. 定期备份数据库文件 `users.db`
5. 系统自动执行聊天记录清理，可在 `.env` 中配置保留天数

## 日志和监控

系统日志文件：
- `server.log`: 服务器运行日志
- `server_output.log`: 服务器输出日志
- `migrate.log`: 数据库迁移日志
- `cleanup_logs.log`: 聊天记录清理日志

## 数据库环境隔离

本项目支持生产环境和开发环境使用不同的数据库文件：

- 生产环境使用：`users.db`
- 开发环境使用：`dev_users.db`

要在开发环境中测试，请在`.env`文件中设置：

```
FLASK_ENV=development
```

这样系统将自动使用`dev_users.db`作为数据库文件。如要切换回生产环境，只需将该设置注释掉或删除。

**注意**：首次在开发环境运行时，会自动创建一个新的`dev_users.db`数据库文件。该文件结构与`users.db`相同，但不包含任何数据。