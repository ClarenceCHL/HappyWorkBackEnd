# Backend Server

这是一个使用 Python 标准库实现的简单后端服务器。

## 运行说明

1. 确保已安装 Python 3.x
2. 在终端中进入 backend 目录
3. 运行命令：`python server.py`
4. 服务器将在 http://localhost:8000 上启动

## API 接口

POST /
- 接收用户的 PUA 相关信息
- 返回针对性的建议和解决方案

请求体格式：
```json
{
  "puaType": "工作成果",
  "severity": "中等",
  "description": "详细描述",
  "perpetrator": "上司"
}
```

响应格式：
```json
{
  "advice": "建议内容",
  "status": "success"
}
```