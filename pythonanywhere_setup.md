# PythonAnywhere 部署指南

## 1. 注册并登录 PythonAnywhere

访问 [pythonanywhere.com](https://www.pythonanywhere.com/) 注册一个账号并登录。

## 2. 上传项目文件

### 方法1：直接上传
1. 在Dashboard页面，点击"Files"选项卡
2. 创建一个新目录，例如 `fkpua_app`
3. 进入该目录，上传所有项目文件
   - 可以先将项目打包成zip文件，上传后解压

### 方法2：使用Git（推荐）
1. 打开"Consoles"选项卡，启动一个Bash控制台
2. 执行如下命令（替换为你的Git仓库URL）：
   ```bash
   mkdir fkpua_app
   cd fkpua_app
   git clone <你的Git仓库URL> .
   ```

## 3. 创建虚拟环境并安装依赖

在Bash控制台中执行：

```bash
cd fkpua_app
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
# 确保额外安装WSGI相关包
pip install werkzeug
```

## 4. 配置Web应用

1. 点击顶部菜单中的"Web"选项卡
2. 点击"Add a new web app"
3. 在向导中选择"Manual configuration"
4. 选择与你本地开发相匹配的Python版本（建议Python 3.9+）
5. 在配置页面填写以下信息：
   - Source code: `/home/你的用户名/fkpua_app`
   - Working directory: `/home/你的用户名/fkpua_app`
   - WSGI configuration file: 默认位置，通常是 `/var/www/你的用户名_pythonanywhere_com_wsgi.py`

## 5. 配置WSGI文件

1. 点击WSGI配置文件链接打开编辑器
2. 删除该文件中的所有内容
3. 粘贴以下内容（替换用户名和应用路径）：

```python
import sys
import os

# 添加你的项目目录到Python路径
path = '/home/你的用户名/fkpua_app'
if path not in sys.path:
    sys.path.append(path)

# 指向你的wsgi.py脚本
from wsgi import application
```

## 6. 配置环境变量

1. 在Web应用配置页面找到"Environment variables"部分
2. 添加以下环境变量（与你的.env文件内容一致）：
   - DEEPSEEK_API_KEY
   - JWT_SECRET
   - EMAIL_FROM
   - EMAIL_USER
   - EMAIL_PASSWORD
   - SMTP_SERVER
   - SMTP_PORT

## 7. 配置数据库

你的应用使用SQLite数据库，确保它有正确的权限：

```bash
chmod 666 users.db
```

## 8. 修改CORS设置

在`wsgi_app.py`文件中，找到以下行：

```python
self.headers.append(('Access-Control-Allow-Origin', '*'))  # 部署时替换为实际前端URL
```

将`*`修改为你的前端应用URL（例如：`https://你的域名.com`）。

## 9. 重启应用

1. 在Web选项卡中点击"Reload"按钮重启你的Web应用
2. 在"Logs"部分查看错误日志，确保应用正确启动

## 10. 测试应用

1. 你的应用现在应该可以通过 `https://你的用户名.pythonanywhere.com` 访问
2. 使用前端应用测试连接，确保API正常工作

## 常见问题排查

1. **500内部服务器错误**：
   - 检查错误日志（Web选项卡下的Error log）
   - 确认所有环境变量已正确设置
   - 检查文件权限，特别是数据库文件

2. **CORS错误**：
   - 确保正确设置Access-Control-Allow-Origin头
   - 前端应用URL必须精确匹配，包括协议（http/https）

3. **依赖问题**：
   - 确保所有必要包都已安装：`pip install -r requirements.txt`
   - 某些包可能需要额外的系统依赖，查阅PythonAnywhere文档

4. **无法发送邮件**：
   - PythonAnywhere限制了部分SMTP服务，参考他们的文档
   - 考虑使用PythonAnywhere支持的邮件服务

## 定期备份

定期备份数据库文件是个好习惯：

```bash
# 添加定时任务备份数据库
mkdir -p ~/backups
cp ~/fkpua_app/users.db ~/backups/users_$(date +%Y%m%d).db
```

## 更新应用

更新应用时，遵循以下步骤：

1. 上传新文件或拉取最新代码：`git pull`
2. 安装新的依赖（如果有）：`pip install -r requirements.txt`
3. 重启应用：点击Web选项卡中的"Reload"按钮 