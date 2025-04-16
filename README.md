# FkCareerPUA 后端服务

这是一个基于 Python 的职场 PUA 应对建议系统后端服务。该系统提供智能化的职场 PUA 场景分析和应对建议，帮助用户更好地处理职场中的不合理要求和不公平对待。

## 功能特点

- 🔐 完整的用户认证系统（注册、登录、验证码）
- 🤖 基于 OpenAI 的智能建议生成
- 💬 实时对话功能
- 📧 邮件验证码系统
- 🔄 会话历史记录
- 🛡️ JWT 身份验证
- 📊 SQLite 数据持久化
- 🧹 聊天记录自动清理功能（可配置保留天数）

## 技术栈

- Python 3.x
- SQLAlchemy (ORM)
- OpenAI API
- JWT 认证
- SQLite 数据库
- SMTP 邮件服务

## 项目结构

```
backend/
├── server.py          # 主服务器文件
├── models.py          # 数据库模型
├── ai_service.py      # AI 服务集成
├── cleanup_chats.py   # 聊天记录清理脚本
├── requirements.txt   # 项目依赖
├── .env              # 环境变量配置
├── templates/        # 邮件模板
└── users.db          # SQLite 数据库文件
```

## 环境要求

- Python 3.x
- 所有依赖包（见 requirements.txt）
- OpenAI API 密钥
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

服务器将在 http://localhost:8000 上启动

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

### 聊天相关

#### 发送消息
- **POST** `/chat/message`
- 请求头：需要 JWT Token
- 请求体：
  ```json
  {
    "message": "用户消息",
    "chatId": "会话ID",
    "mode": "simulation"
  }
  ```

#### 获取聊天历史
- **GET** `/chat/{chatId}`
- 请求头：需要 JWT Token

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
```

## 开发工具

- `create_test_user.py`: 创建测试用户
- `migrate_db.py`: 数据库迁移工具
- `check_table.py`: 数据库表检查工具
- `cleanup_chats.py`: 手动清理过期聊天记录

## 注意事项

1. 确保 OpenAI API 密钥配置正确
2. 邮件服务器配置需要正确设置
3. 生产环境部署时请修改 CORS 设置
4. 建议使用环境变量管理敏感信息

## 贡献指南

1. Fork 项目
2. 创建特性分支
3. 提交更改
4. 推送到分支
5. 创建 Pull Request

## 许可证

[MIT License](LICENSE)