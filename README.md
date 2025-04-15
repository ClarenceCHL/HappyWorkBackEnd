# 职场PUA咨询与应对系统后端

这是一个基于Python实现的专业职场PUA（心理操控）咨询与应对系统后端服务。系统提供两种模式：PUA场景模拟和专业应对解决方案，帮助用户理解和应对职场中的PUA行为。

## 功能特点

- **用户认证系统**：支持邮箱注册、登录、验证码验证和密码管理
- **聊天系统**：保存用户与AI助手的对话历史记录
- **AI模拟模式**：模拟职场PUA行为，帮助用户认识和理解PUA话术
- **AI解决方案模式**：提供专业的反PUA建议，帮助用户应对职场PUA情境
- **数据持久化**：使用SQLite数据库存储用户信息与聊天记录
- **安全认证**：基于JWT的身份验证和授权系统

## 技术栈

- **基础框架**：Python标准库中的HTTPServer
- **AI对话**：DeepSeek API（大模型服务）
- **数据库**：SQLAlchemy ORM + SQLite
- **认证**：PyJWT
- **邮件服务**：SMTP客户端
- **部署支持**：WSGI适配（支持PythonAnywhere等平台部署）

## 安装说明

1. 克隆代码库到本地
2. 安装依赖包：
```bash
pip install -r requirements.txt
```
3. 配置环境变量（创建`.env`文件）：
```
DEEPSEEK_API_KEY=your_deepseek_api_key
JWT_SECRET=your_jwt_secret_key
EMAIL_FROM=your_email@example.com
EMAIL_USER=your_email_user
EMAIL_PASSWORD=your_email_password
SMTP_SERVER=your_smtp_server
SMTP_PORT=your_smtp_port
```

## 本地运行

```bash
python server.py
```
服务器将在本地8000端口启动

## API文档

### 用户认证

- **POST /send_code**：发送验证码
- **POST /verify_code**：验证验证码
- **POST /register**：用户注册
- **POST /login**：用户登录
- **POST /change_password**：修改密码

### 聊天功能

- **POST /**：创建新的聊天
- **POST /chat/message**：发送聊天消息
- **POST /chat/follow_up**：继续对话
- **GET /chat/:id**：获取聊天历史

### 用户信息

- **GET /user/info**：获取用户信息

## 部署指南

项目支持标准WSGI部署，详细部署步骤请参考`pythonanywhere_setup.md`文件。

## 数据库结构

- **users**: 用户信息表
- **verification_codes**: 验证码表
- **chats**: 聊天记录表
- **messages**: 消息表

## 安全注意事项

- 确保妥善保管环境变量中的敏感信息
- 生产环境中建议使用HTTPS
- 定期更新依赖以修复潜在安全问题

## 许可证

私有软件，未经授权不得使用