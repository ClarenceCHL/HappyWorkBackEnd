import os
import sys
import json
from io import BytesIO
import jwt
from urllib.parse import parse_qs
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()

# 导入原始服务器模块中的处理逻辑
sys.path.insert(0, os.path.dirname(__file__))
from server import AuthHandler, run
from models import engine, Session

class WSGIRequestHandler:
    """适配HTTP请求处理器到WSGI环境"""
    
    def __init__(self, environ, start_response):
        self.environ = environ
        self.start_response = start_response
        self.headers = []
        self.status = '200 OK'
        
    def send_response(self, code):
        """模拟HTTP响应状态设置"""
        status_messages = {
            200: 'OK',
            201: 'Created',
            400: 'Bad Request',
            401: 'Unauthorized',
            403: 'Forbidden',
            404: 'Not Found',
            500: 'Internal Server Error'
        }
        message = status_messages.get(code, '')
        self.status = f"{code} {message}"
    
    def send_header(self, name, value):
        """模拟HTTP响应头设置"""
        self.headers.append((name, value))
    
    def end_headers(self):
        """完成头部设置"""
        pass
    
    def get_post_data(self):
        """获取POST请求数据"""
        try:
            content_length = int(self.environ.get('CONTENT_LENGTH', 0))
            post_data = self.environ['wsgi.input'].read(content_length)
            return json.loads(post_data.decode('utf-8'))
        except (ValueError, KeyError, json.JSONDecodeError):
            return {}
    
    def get_auth_header(self):
        """获取授权头"""
        auth_header = self.environ.get('HTTP_AUTHORIZATION')
        return auth_header
    
    def get_path(self):
        """获取请求路径"""
        return self.environ['PATH_INFO']
    
    def handle_request(self):
        """处理WSGI请求"""
        method = self.environ['REQUEST_METHOD']
        
        # 创建一个模拟的HTTP处理器
        auth_handler = AuthHandler.__new__(AuthHandler)
        auth_handler.headers = self
        auth_handler.path = self.get_path()
        auth_handler.send_response = self.send_response
        auth_handler.send_header = self.send_header
        auth_handler.end_headers = self.end_headers
        auth_handler.wfile = BytesIO()
        
        if method == 'OPTIONS':
            auth_handler._set_response_headers = lambda: None
            auth_handler.do_OPTIONS()
        elif method == 'GET':
            auth_handler._set_response_headers = lambda: None
            auth_handler.do_GET()
        elif method == 'POST':
            auth_handler.rfile = BytesIO(json.dumps(self.get_post_data()).encode('utf-8'))
            auth_handler.headers = {'Content-Length': len(auth_handler.rfile.getvalue())}
            auth_handler._set_response_headers = lambda: None
            auth_handler.do_POST()
        else:
            self.send_response(405)
            self.send_header('Content-Type', 'application/json')
            auth_handler.wfile.write(json.dumps({"status": "error", "message": "Method not allowed"}).encode('utf-8'))
        
        # 获取响应内容
        response_body = auth_handler.wfile.getvalue()
        
        # 设置CORS响应头，替换为实际前端URL
        self.headers.append(('Access-Control-Allow-Origin', '*'))  # 部署时替换为实际前端URL
        self.headers.append(('Access-Control-Allow-Methods', 'GET, POST, OPTIONS'))
        self.headers.append(('Access-Control-Allow-Headers', 'Content-Type, Authorization'))
        self.headers.append(('Access-Control-Max-Age', '86400'))
        
        self.start_response(self.status, self.headers)
        return [response_body]

def application(environ, start_response):
    """WSGI应用入口点"""
    try:
        handler = WSGIRequestHandler(environ, start_response)
        return handler.handle_request()
    except Exception as e:
        start_response('500 Internal Server Error', [('Content-Type', 'application/json')])
        error_message = {"status": "error", "message": f"服务器内部错误: {str(e)}"}
        return [json.dumps(error_message).encode('utf-8')]

# 测试运行服务器
if __name__ == '__main__':
    from wsgiref.simple_server import make_server
    httpd = make_server('localhost', 8000, application)
    print("在端口8000启动测试服务器...")
    httpd.serve_forever() 