from http.server import HTTPServer, BaseHTTPRequestHandler
import json
from sqlalchemy.orm import sessionmaker
from models import engine, User, VerificationCode, Chat, Message, Questionnaire, QuestionnaireResponse
import jwt
from datetime import datetime, timedelta, UTC
import smtplib
from email.mime.text import MIMEText
import os
from dotenv import load_dotenv
from ai_service import generate_pua_response, generate_questionnaire_report, save_questionnaire, save_questionnaire_response
from werkzeug.security import generate_password_hash
import sqlite3
import threading
import time
from cleanup_chats import cleanup_old_chats
import logging
from urllib.parse import urlparse, parse_qs

# 设置日志配置
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(os.path.dirname(__file__), 'server.log'))
    ]
)
logger = logging.getLogger(__name__)

# 加载环境变量
load_dotenv()

# 创建数据库会话
Session = sessionmaker(bind=engine)

def get_allowed_origins():
    """从环境变量获取允许的域名列表"""
    # 从环境变量获取允许的域名，多个域名用逗号分隔
    allowed_origins = os.getenv('ALLOWED_ORIGINS')
    if not allowed_origins:
        # 如果环境变量未设置或为空，可以抛出错误或返回空列表
        # 这里选择返回空列表，让后续的CORS检查处理
        # 或者你可以选择抛出异常: raise ValueError("ALLOWED_ORIGINS environment variable is not set.")
        return []
    # 分割并去除空白字符
    return [origin.strip() for origin in allowed_origins.split(',')]

class AuthHandler(BaseHTTPRequestHandler):
    def _set_response_headers(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        
        # 获取请求的Origin
        origin = self.headers.get('Origin')
        # 获取允许的域名列表
        allowed_origins = get_allowed_origins()
        
        # 如果请求的Origin在允许列表中，则设置对应的CORS头
        if origin in allowed_origins:
            self.send_header('Access-Control-Allow-Origin', origin)
            self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, DELETE')
            self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
            self.send_header('Access-Control-Max-Age', '86400')
        
        self.end_headers()

    def _serve_static_file(self, file_path, content_type='text/html'):
        """专门处理静态文件的函数"""
        try:
            with open(file_path, 'rb') as file:
                content = file.read()
                
            # 设置HTTP响应头
            self.send_response(200)
            self.send_header('Content-Type', f'{content_type}; charset=utf-8')
            self.send_header('Content-Length', str(len(content)))
            
            # 添加标准缓存控制头
            self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
            self.send_header('Pragma', 'no-cache')
            self.send_header('Expires', '0')
            
            # 添加安全相关头
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header('X-XSS-Protection', '1; mode=block')
            
            # 添加CORS头
            origin = self.headers.get('Origin', '*')
            allowed_origins = get_allowed_origins()
            if origin in allowed_origins or origin == '*':
                self.send_header('Access-Control-Allow-Origin', origin)
                self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, DELETE')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
            
            # 完成头部设置
            self.end_headers()
            
            # 发送文件内容
            self.wfile.write(content)
            print(f"成功发送静态文件: {file_path}, 内容类型: {content_type}, 大小: {len(content)}字节")
            return True
        except FileNotFoundError:
            print(f"文件未找到: {file_path}")
            return False
        except Exception as e:
            print(f"处理静态文件时出错: {str(e)}")
            return False

    def do_OPTIONS(self):
        self._set_response_headers()
        self.wfile.write(b'')

    def do_GET(self):
        # 处理静态HTML页面
        if self.path == '/admin':
            admin_html_path = 'templates/admin.html'
            if self._serve_static_file(admin_html_path):
                return
            else:
                # 文件不存在，返回错误信息
                self._set_response_headers()
                response = {"status": "error", "message": "管理页面不存在"}
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return
        # 处理预览报告
        elif self.path.startswith('/preview/'):
            # 打印完整的路径和路径部分，帮助调试
            path_components = self.path.split('/')
            preview_id = path_components[-1] if len(path_components) > 2 else ""
            
            print(f"处理预览请求，完整路径: {self.path}")
            print(f"请求方法: {self.command}")
            print(f"路径组件: {path_components}")
            print(f"提取的预览ID: {preview_id}")
            print(f"请求头: {dict(self.headers)}")
            
            # 检查是否为AJAX请求，如果是JSON请求则返回JSON数据
            accept_header = self.headers.get('Accept', '')
            print(f"预览请求Accept头: {accept_header}")
            
            if 'application/json' in accept_header:
                print(f"处理为JSON请求: {self.path}, 预览ID: {preview_id}")
                if not preview_id:
                    print("错误: 预览ID为空")
                    self._set_response_headers()
                    response = {"status": "error", "message": "缺少预览ID"}
                    self.wfile.write(json.dumps(response).encode('utf-8'))
                    return
                
                try:
                    print(f"调用handle_preview_report，预览ID: {preview_id}")
                    response = self.handle_preview_report(preview_id)
                    print(f"预览报告响应状态: {response.get('status')}")
                    if response.get('status') == 'success':
                        report_content = response.get('report', '')
                        content_length = len(report_content) if report_content else 0
                        sample = report_content[:100] + '...' if content_length > 100 else report_content
                        print(f"报告内容长度: {content_length}")
                        print(f"报告内容示例: {sample}")
                    
                    self._set_response_headers()
                    response_json = json.dumps(response)
                    self.wfile.write(response_json.encode('utf-8'))
                    print(f"已发送JSON响应，长度: {len(response_json)}")
                    return
                except Exception as e:
                    print(f"处理预览报告请求时出错: {str(e)}")
                    import traceback
                    traceback.print_exc()
                    self._set_response_headers()
                    response = {"status": "error", "message": f"服务器处理错误: {str(e)}"}
                    self.wfile.write(json.dumps(response).encode('utf-8'))
                    return
            else:
                # 如果是常规浏览器请求，返回HTML页面
                print(f"处理为HTML页面请求: {self.path}")
                preview_html_path = 'templates/preview_report.html'
                if self._serve_static_file(preview_html_path, 'text/html'):
                    print(f"成功发送HTML页面: {preview_html_path}")
                    return
                else:
                    print(f"错误: HTML页面不存在: {preview_html_path}")
                    self._set_response_headers()
                    response = {"status": "error", "message": "预览页面不存在"}
                    self.wfile.write(json.dumps(response).encode('utf-8'))
                    return
        
        # 其他API路径使用通用头
        self._set_response_headers()
        
        print(f"接收到GET请求: {self.path}")
        
        # 验证 token
        auth_header = self.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            response = {"status": "error", "message": "未授权访问"}
            self.wfile.write(json.dumps(response).encode('utf-8'))
            return
            
        token = auth_header.split(' ')[1]
        try:
            # 验证 token
            payload = jwt.decode(token, os.getenv('JWT_SECRET', 'your-secret-key'), algorithms=['HS256'])
            user_id = payload['user_id']
            is_admin = payload.get('is_admin', False)
            
            # 检查是否是管理员API请求
            if self.path.startswith('/admin/'):
                # 验证管理员权限
                if not is_admin:
                    response = {"status": "error", "message": "需要管理员权限"}
                    self.wfile.write(json.dumps(response).encode('utf-8'))
                    return
                
                # 处理带查询参数的chat_details请求
                if self.path.startswith('/admin/chat_details?'):
                    parsed_url = urlparse(self.path)
                    query_params = parse_qs(parsed_url.query)
                    chat_id = query_params.get('chat_id', [''])[0]
                    if chat_id:
                        response = self.handle_admin_chat_details(chat_id)
                    else:
                        response = {"status": "error", "message": "缺少聊天ID参数"}
                # 处理删除聊天记录请求
                elif self.path.startswith('/admin/delete_chat?'):
                    parsed_url = urlparse(self.path)
                    query_params = parse_qs(parsed_url.query)
                    chat_id = query_params.get('chat_id', [''])[0]
                    if chat_id:
                        response = self.handle_admin_delete_chat(chat_id)
                    else:
                        response = {"status": "error", "message": "缺少聊天ID参数"}
                # 管理员API路由
                elif self.path == '/admin/users':
                    response = self.handle_admin_users()
                elif self.path == '/admin/chats':
                    response = self.handle_admin_chats()
                elif self.path == '/admin/stats':
                    response = self.handle_admin_stats()
                elif self.path.startswith('/admin/chat_details/'):
                    # 从路径中提取聊天ID
                    chat_id = self.path.split('/')[-1]
                    response = self.handle_admin_chat_details(chat_id)
                else:
                    response = {"status": "error", "message": "无效的管理员API路径"}
            # 检查是否是获取用户信息的请求
            elif self.path == '/user/info':
                response = self.handle_get_user_info(user_id)
            # 检查是否是获取用户问卷列表的请求
            elif self.path == '/user/questionnaires':
                response = self.handle_get_user_questionnaires(user_id)
            # 检查是否是获取所有聊天历史的请求
            elif self.path == '/chat/history':
                response = self.handle_get_all_chats(user_id)
            # 检查是否是获取单个聊天记录的请求
            elif self.path.startswith('/chat/') and self.path != '/chat/history':
                chat_id = self.path.split('/')[-1]
                if not chat_id:
                    response = {"status": "error", "message": "缺少聊天ID"}
                else:
                    response = self.handle_get_chat_history(user_id, chat_id)
            else:
                response = {"status": "error", "message": "Invalid endpoint"}
                
        except jwt.ExpiredSignatureError:
            response = {"status": "error", "message": "登录已过期"}
        except jwt.InvalidTokenError:
            response = {"status": "error", "message": "无效的认证信息"}
        except Exception as e:
            print(f"处理请求时出错: {str(e)}")
            response = {"status": "error", "message": str(e)}
            
        # 发送响应
        self.wfile.write(json.dumps(response).encode('utf-8'))

    def do_POST(self):
        self._set_response_headers()
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        data = json.loads(post_data.decode('utf-8'))
        
        if self.path == '/send_code':
            response = self.handle_send_code(data)
        elif self.path == '/verify_code':
            response = self.handle_verify_code(data)
        elif self.path == '/login':
            response = self.handle_login(data)
        elif self.path == '/register':
            response = self.handle_register(data)
        elif self.path == '/change_password':
            # 验证token
            auth_header = self.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                response = {"status": "error", "message": "未授权访问"}
            else:
                token = auth_header.split(' ')[1]
                try:
                    # 验证token
                    payload = jwt.decode(token, os.getenv('JWT_SECRET', 'your-secret-key'), algorithms=['HS256'])
                    user_id = payload['user_id']
                    response = self.handle_change_password(data, user_id)
                except jwt.ExpiredSignatureError:
                    response = {"status": "error", "message": "登录已过期"}
                except jwt.InvalidTokenError:
                    response = {"status": "error", "message": "无效的认证信息"}
        elif self.path == '/admin/clear_all_chats':
            # 验证管理员token
            auth_header = self.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                response = {"status": "error", "message": "未授权访问"}
            else:
                token = auth_header.split(' ')[1]
                try:
                    # 验证token
                    payload = jwt.decode(token, os.getenv('JWT_SECRET', 'your-secret-key'), algorithms=['HS256'])
                    is_admin = payload.get('is_admin', False)
                    
                    if not is_admin:
                        response = {"status": "error", "message": "需要管理员权限"}
                    else:
                        response = self.handle_admin_clear_all_chats()
                except jwt.ExpiredSignatureError:
                    response = {"status": "error", "message": "登录已过期"}
                except jwt.InvalidTokenError:
                    response = {"status": "error", "message": "无效的认证信息"}
        elif self.path == '/admin/add_admin':
            # 验证管理员token
            auth_header = self.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                response = {"status": "error", "message": "未授权访问"}
            else:
                token = auth_header.split(' ')[1]
                try:
                    # 验证token
                    payload = jwt.decode(token, os.getenv('JWT_SECRET', 'your-secret-key'), algorithms=['HS256'])
                    is_admin = payload.get('is_admin', False)

                    if not is_admin:
                        response = {"status": "error", "message": "需要管理员权限"}
                    else:
                        # 调用新的处理函数
                        response = self.handle_add_admin(data)
                except jwt.ExpiredSignatureError:
                    response = {"status": "error", "message": "登录已过期"}
                except jwt.InvalidTokenError:
                    response = {"status": "error", "message": "无效的认证信息"}
                except Exception as e:
                    logger.error(f"添加管理员时出错: {e}", exc_info=True)
                    response = {"status": "error", "message": f"处理请求时发生内部错误: {e}"}
        elif self.path == '/api/activate-free-access':
            auth_header = self.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                response = {"status": "error", "message": "未授权访问"}
            else:
                token = auth_header.split(' ')[1]
                try:
                    payload = jwt.decode(token, os.getenv('JWT_SECRET', 'your-secret-key'), algorithms=['HS256'])
                    user_id = payload['user_id']
                    
                    session = Session()
                    try:
                        user = session.query(User).filter(User.id == user_id).first()
                        if user:
                            user.is_paid = True
                            session.commit()
                            response = {"status": "success", "message": "免费访问已激活"}
                            logger.info(f"用户 {user_id} 激活了免费访问")
                        else:
                            response = {"status": "error", "message": "用户不存在"}
                    except Exception as e:
                        session.rollback()
                        logger.error(f"激活免费访问时数据库出错 (用户 {user_id}): {str(e)}")
                        response = {"status": "error", "message": f"数据库错误: {str(e)}"}
                    finally:
                        session.close()

                except jwt.ExpiredSignatureError:
                    response = {"status": "error", "message": "登录已过期"}
                except jwt.InvalidTokenError:
                    response = {"status": "error", "message": "无效的认证信息"}
                except Exception as e:
                    logger.error(f"处理 /api/activate-free-access 时发生未知错误: {str(e)}")
                    response = {"status": "error", "message": f"处理请求时出错: {str(e)}"}
        elif self.path == '/chat/message':  # 处理聊天消息
            # 验证 token
            auth_header = self.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                response = {"status": "error", "message": "未授权访问"}
            else:
                token = auth_header.split(' ')[1]
                try:
                    # 验证 token
                    payload = jwt.decode(token, os.getenv('JWT_SECRET', 'your-secret-key'), algorithms=['HS256'])
                    user_id = payload['user_id']
                    
                    # 检查是否提供了mode参数
                    if 'mode' not in data:
                        response = {"status": "error", "message": "缺少mode参数，请选择对话模式：'simulation'(场景模拟)或'solution'(解决方案)"}
                        self.wfile.write(json.dumps(response).encode('utf-8'))
                        return
                    
                    # 验证mode参数值是否有效
                    if data['mode'] not in ['simulation', 'solution']:
                        response = {"status": "error", "message": "mode参数值无效，只能是'simulation'(场景模拟)或'solution'(解决方案)"}
                        self.wfile.write(json.dumps(response).encode('utf-8'))
                        return
                    
                    # 完全修改后的处理逻辑
                    print("=" * 80)
                    print(f"[/chat/message] 处理聊天消息，用户ID: {user_id}")
                    print(f"[/chat/message] 接收到的完整数据: {data}")
                    print(f"[/chat/message] 前端传入的Mode参数: {data['mode']}")
                    
                    # 直接调用handle_chat_message处理
                    ai_response = self.handle_chat_message(data)
                    print(f"[/chat/message] AI响应: {ai_response}")
                    print(f"[/chat/message] 最终使用的模式: {ai_response.get('mode')}")
                    print("=" * 80)
                    
                    # 如果成功生成回复，保存到数据库
                    if ai_response['status'] == 'success':
                        session = Session()
                        try:
                            chat_id = data.get('chatId')
                            if not chat_id:
                                response = {"status": "error", "message": "缺少聊天ID"}
                                self.wfile.write(json.dumps(response).encode('utf-8'))
                                return
                            
                            # 保存用户消息
                            user_message = Message(
                                chat_id=chat_id,
                                role='user',
                                content=data.get('message', ''),
                                form_data=json.dumps(data.get('images', []))
                            )
                            session.add(user_message)
                            
                            # 保存AI回复
                            ai_message = Message(
                                chat_id=chat_id,
                                role='assistant',
                                content=ai_response['advice']
                            )
                            session.add(ai_message)
                            
                            # 更新聊天的最后活动时间
                            chat = session.query(Chat).filter(Chat.id == chat_id).first()
                            if chat:
                                chat.last_activity = datetime.now(UTC)
                            
                            session.commit()
                            
                            # 设置响应
                            response = {
                                "status": "success",
                                "advice": ai_response['advice'],
                                "mode": ai_response['mode']  # 使用AI响应中的模式
                            }
                            print(f"[/chat/message] 返回给前端的模式: {response['mode']}")
                        except Exception as e:
                            session.rollback()
                            print(f"保存消息失败: {str(e)}")
                            response = {"status": "error", "message": f"保存消息失败: {str(e)}"}
                        finally:
                            session.close()
                    else:
                        response = ai_response
                except jwt.ExpiredSignatureError:
                    response = {"status": "error", "message": "登录已过期"}
                except jwt.InvalidTokenError:
                    response = {"status": "error", "message": "无效的认证信息"}
                except Exception as e:
                    print(f"处理聊天消息时出错: {str(e)}")
        # 添加问卷提交路由
        elif self.path == '/questionnaire/submit':
            # 验证token
            auth_header = self.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                response = {"status": "error", "message": "未授权访问"}
            else:
                token = auth_header.split(' ')[1]
                try:
                    # 验证token
                    payload = jwt.decode(token, os.getenv('JWT_SECRET', 'your-secret-key'), algorithms=['HS256'])
                    user_id = payload['user_id']
                    
                    print(f"收到问卷提交请求，用户ID: {user_id}")
                    print(f"问卷数据: {data}")
                    
                    # 处理问卷提交
                    response = self.handle_questionnaire_submit(user_id, data)
                    print(f"问卷处理结果: {response}")
                except jwt.ExpiredSignatureError:
                    response = {"status": "error", "message": "登录已过期"}
                except jwt.InvalidTokenError:
                    response = {"status": "error", "message": "无效的认证信息"}
                except Exception as e:
                    logger.error(f"处理问卷提交时出错: {str(e)}")
                    print(f"处理问卷提交时出错: {str(e)}")
                    import traceback
                    traceback.print_exc()
                    response = {"status": "error", "message": f"处理问卷提交时出错: {str(e)}"}
        elif self.path == '/chat/follow_up':  # 处理后续对话
            # 验证 token
            auth_header = self.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                response = {"status": "error", "message": "未授权访问"}
            else:
                token = auth_header.split(' ')[1]
                try:
                    # 验证 token
                    payload = jwt.decode(token, os.getenv('JWT_SECRET', 'your-secret-key'), algorithms=['HS256'])
                    user_id = payload['user_id']
                    
                    # 调用处理函数
                    data['user_id'] = user_id
                    response = self.handle_chat_message(data)
                except jwt.ExpiredSignatureError:
                    response = {"status": "error", "message": "登录已过期"}
                except jwt.InvalidTokenError:
                    response = {"status": "error", "message": "无效的认证信息"}
                except Exception as e:
                    print(f"处理后续对话时出错: {str(e)}")
                    response = {"status": "error", "message": str(e)}
        elif self.path == '/':  # 处理新建咨询请求
            # 验证 token
            auth_header = self.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                response = {"status": "error", "message": "未授权访问"}
            else:
                token = auth_header.split(' ')[1]
                try:
                    # 验证 token
                    payload = jwt.decode(token, os.getenv('JWT_SECRET', 'your-secret-key'), algorithms=['HS256'])
                    user_id = payload['user_id']
                    
                    print("=" * 80)
                    print(f"[/] 处理新建咨询请求，用户ID: {user_id}")
                    print(f"[/] 接收到的完整数据: {data}")
                    print(f"[/] 前端传入的Mode参数: {data.get('mode')}")
                    
                    # 检查是否提供了mode参数
                    if 'mode' not in data:
                        response = {"status": "error", "message": "缺少mode参数，请选择对话模式：'simulation'(场景模拟)或'solution'(解决方案)"}
                        self.wfile.write(json.dumps(response).encode('utf-8'))
                        return
                    
                    # 验证mode参数值是否有效
                    if data['mode'] not in ['simulation', 'solution']:
                        response = {"status": "error", "message": "mode参数值无效，只能是'simulation'(场景模拟)或'solution'(解决方案)"}
                        self.wfile.write(json.dumps(response).encode('utf-8'))
                        return
                    
                    # 记录用户选择的确定模式
                    selected_mode = data['mode']
                    logger.info(f"新建咨询使用模式: {selected_mode}")
                    print(f"[/] 选择的模式: {selected_mode}")
                    
                    # 构建咨询数据，确保mode参数正确传递
                    chat_data = {
                        'type': 'initial',
                        'puaType': data.get('puaType', []),
                        'severity': data.get('severity', ''),
                        'perpetrator': data.get('perpetrator', []),
                        'description': data.get('description', ''),
                        'mode': selected_mode
                    }
                    
                    # 生成回复
                    ai_response = generate_pua_response(chat_data)
                    print(f"[/] AI响应: {ai_response}")
                    
                    # 如果生成成功，保存对话记录
                    if ai_response['status'] == 'success':
                        session = Session()
                        try:
                            # 创建新的聊天，将mode保存到标题中以便前端显示
                            mode_text = "场景模拟" if selected_mode == 'simulation' else "解决方案"
                            title_prefix = f"[{mode_text}] "
                            chat_title = title_prefix + (', '.join(data.get('puaType', [])) if 'puaType' in data else '新对话')
                            print(f"[/] 创建聊天标题: {chat_title}")
                            
                            chat = Chat(
                                user_id=user_id,
                                title=chat_title
                            )
                            session.add(chat)
                            session.flush()  # 获取chat.id
                            print(f"[/] 创建聊天记录，ID: {chat.id}")
                            
                            # 保存用户消息
                            user_message = Message(
                                chat_id=chat.id,
                                role='user',
                                content=f"遭遇类型：{', '.join(data.get('puaType', []))}\n严重程度：{data.get('severity', '')}\n施害者：{', '.join(data.get('perpetrator', []))}\n\n{data.get('description', '')}",
                                form_data=json.dumps(data.get('images', []))
                            )
                            session.add(user_message)
                            
                            # 保存AI回复
                            ai_message = Message(
                                chat_id=chat.id,
                                role='assistant',
                                content=ai_response['advice']
                            )
                            session.add(ai_message)
                            
                            # 更新聊天的最后活动时间
                            chat.last_activity = datetime.now(UTC)
                            
                            session.commit()
                            print(f"[/] 聊天记录保存成功，ID: {chat.id}, 类型: {type(chat.id)}, 标题: {chat.title}")
                            
                            # 查看所有聊天，用于调试
                            all_chats = session.query(Chat).order_by(Chat.created_at.desc()).limit(5).all()
                            print(f"[/] 最近5条聊天记录:")
                            for c in all_chats:
                                print(f"[/] - ID: {c.id}, 类型: {type(c.id)}, 标题: {c.title}")
                            
                            # 前端传回的chatId会是什么类型？
                            frontend_chat_id = str(int(datetime.now().timestamp() * 1000))
                            print(f"[/] 当前时间戳(前端可能使用): {frontend_chat_id}")
                            
                            response = {
                                "status": "success",
                                "advice": ai_response['advice'],
                                "mode": selected_mode,  # 返回用户选择的模式给前端
                                "chatId": chat.id  # 添加chatId返回给前端
                            }
                            print(f"[/] 返回给前端的数据: {response}")
                            print("=" * 80)
                            
                        except Exception as e:
                            session.rollback()
                            print(f"[/] 保存对话失败: {str(e)}")
                            import traceback
                            traceback.print_exc()
                            response = {"status": "error", "message": f"保存对话失败: {str(e)}"}
                        finally:
                            session.close()
                    else:
                        # 确保错误响应也包含正确的模式
                        if 'mode' not in ai_response:
                            ai_response['mode'] = selected_mode
                        response = ai_response
                        
                except jwt.ExpiredSignatureError:
                    response = {"status": "error", "message": "登录已过期"}
                except jwt.InvalidTokenError:
                    response = {"status": "error", "message": "无效的认证信息"}
        else:
            response = {"status": "error", "message": "Invalid endpoint"}
        
        self.wfile.write(json.dumps(response).encode('utf-8'))

    def do_DELETE(self):
        """处理DELETE请求"""
        self._set_response_headers()
        
        # 验证token
        auth_header = self.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            response = {"status": "error", "message": "未授权访问"}
            self.wfile.write(json.dumps(response).encode('utf-8'))
            return
        
        token = auth_header.split(' ')[1]
        try:
            # 验证token
            payload = jwt.decode(token, os.getenv('JWT_SECRET', 'your-secret-key'), algorithms=['HS256'])
            requesting_admin_id = payload['user_id'] # 获取发起请求的管理员ID
            is_admin = payload.get('is_admin', False)
            
            # 验证管理员权限
            if not is_admin:
                response = {"status": "error", "message": "需要管理员权限"}
                self.wfile.write(json.dumps(response).encode('utf-8'))
                return
            
            parsed_url = urlparse(self.path)
            query_params = parse_qs(parsed_url.query)
            
            # 处理删除单个聊天记录的请求
            if self.path.startswith('/admin/delete_chat?'):
                chat_id = query_params.get('chat_id', [''])[0]
                
                if chat_id:
                    response = self.handle_admin_delete_chat(chat_id)
                else:
                    response = {"status": "error", "message": "缺少聊天ID参数"}
            
            # 处理清除所有聊天记录的请求
            elif self.path == '/admin/clear_all_chats':
                response = self.handle_admin_clear_all_chats()
            
            # 新增：处理删除用户的请求
            elif self.path.startswith('/admin/delete_user?'):
                user_id_to_delete_str = query_params.get('user_id', [''])[0]
                if user_id_to_delete_str:
                    try:
                        user_id_to_delete = int(user_id_to_delete_str)
                        response = self.handle_admin_delete_user(requesting_admin_id, user_id_to_delete)
                    except ValueError:
                        response = {"status": "error", "message": "无效的用户ID格式"}
                else:
                    response = {"status": "error", "message": "缺少用户ID参数"}
                    
            else:
                response = {"status": "error", "message": "无效的API路径"}
            
        except jwt.ExpiredSignatureError:
            response = {"status": "error", "message": "登录已过期"}
        except jwt.InvalidTokenError:
            response = {"status": "error", "message": "无效的认证信息"}
        except Exception as e:
            response = {"status": "error", "message": str(e)}
        
        self.wfile.write(json.dumps(response).encode('utf-8'))

    def handle_get_chat_history(self, user_id, chat_id):
        session = Session()
        try:
            # 获取聊天记录，并确保是当前用户的
            chat = session.query(Chat).filter(
                Chat.id == chat_id,
                Chat.user_id == user_id
            ).first()
            
            if not chat:
                return {"status": "error", "message": "找不到对话记录"}
            
            # 获取所有消息
            messages = []
            for message in chat.messages:
                messages.append({
                    "role": message.role,
                    "content": message.content,
                    "timestamp": message.created_at.isoformat(),
                    "form_data": json.loads(message.form_data) if message.form_data else []  # 将 JSON 字符串转回 Python 对象
                })
            
            return {
                "status": "success",
                "messages": messages
            }
            
        except Exception as e:
            return {"status": "error", "message": str(e)}
        finally:
            session.close()

    def handle_get_user_info(self, user_id):
        session = Session()
        try:
            user = session.query(User).filter(User.id == user_id).first()
            
            if not user:
                return {"status": "error", "message": "用户不存在"}
            
            # 同时返回 email, is_paid 和 has_pdf 状态
            return {
                "status": "success",
                "email": user.email,
                "is_paid": user.is_paid, 
                "has_pdf": user.has_pdf # 添加 has_pdf 字段
            }
            
        except Exception as e:
            return {"status": "error", "message": str(e)}
        finally:
            session.close()

    def handle_get_all_chats(self, user_id):
        """获取用户的所有聊天历史记录"""
        session = Session()
        try:
            print(f"正在获取用户ID:{user_id}的所有聊天历史")
            
            # 获取用户的所有聊天，按创建时间倒序排列（最新的在前）
            chats = session.query(Chat).filter(
                Chat.user_id == user_id
            ).order_by(Chat.created_at.desc()).all()
            
            print(f"找到{len(chats)}条聊天记录")
            
            # 格式化返回数据
            chat_list = []
            for chat in chats:
                # 获取最后一条消息作为预览
                last_message = None
                if chat.messages:
                    last_message = chat.messages[-1]
                
                # 提取聊天类型（从标题中）
                chat_type = 'solution'  # 默认为解决方案模式
                if chat.title and '[场景模拟]' in chat.title:
                    chat_type = 'simulation'
                
                # 构建消息列表
                messages = []
                for msg in chat.messages:
                    messages.append({
                        "role": msg.role,
                        "content": msg.content,
                        "timestamp": msg.created_at.isoformat(),
                        "images": json.loads(msg.form_data) if msg.form_data else []
                    })
                
                chat_data = {
                    "id": chat.id,
                    "title": chat.title,
                    "timestamp": chat.created_at.isoformat(),
                    "preview": last_message.content if last_message else "",
                    "type": chat_type,
                    "messages": messages
                }
                chat_list.append(chat_data)
            
            print(f"成功格式化{len(chat_list)}条聊天记录")
            
            return {
                "status": "success",
                "chats": chat_list
            }
            
        except Exception as e:
            print(f"获取聊天历史失败: {str(e)}")
            return {"status": "error", "message": str(e)}
        finally:
            session.close()

    def handle_send_code(self, data):
        session = Session()
        try:
            identifier = data.get('identifier')
            mode = data.get('mode', 'register')  # 默认为注册模式
            
            if not identifier:
                return {"status": "error", "message": "请输入邮箱"}
            
            # 验证邮箱格式
            is_email = User.is_valid_email(identifier)
            
            if not is_email:
                return {"status": "error", "message": "无效的邮箱格式"}
            
            # 检查是否已注册
            user = session.query(User).filter(User.email == identifier).first()
            
            # 根据模式进行不同的验证
            if mode == 'register' and user and user.is_verified:
                return {"status": "error", "message": "该邮箱已注册"}
            elif mode == 'login' and (not user or not user.is_verified):
                return {"status": "error", "message": "该邮箱未注册"}
            
            # 生成验证码
            code = VerificationCode.generate_code()
            current_time = datetime.now(UTC)
            expires_at = current_time + timedelta(minutes=5)
            
            # 使用SQLAlchemy ORM保存验证码
            new_code = VerificationCode(
                identifier=identifier,
                code=code,
                created_at=current_time,
                expires_at=expires_at,
                is_used=False
            )
            session.add(new_code)
            session.commit()
            
            # 发送验证码
            self.send_email_code(identifier, code)
            
            return {"status": "success", "message": "验证码已发送，请查收邮件"}
            
        except Exception as e:
            session.rollback()
            print(f"发送验证码失败: {str(e)}")  # 添加错误日志
            return {"status": "error", "message": str(e)}
        finally:
            session.close()

    def handle_verify_code(self, data):
        session = Session()
        try:
            identifier = data.get('identifier')
            code = data.get('code')
            
            if not identifier or not code:
                return {"status": "error", "message": "缺少必要信息"}
            
            # 验证邮箱格式
            if not User.is_valid_email(identifier):
                return {"status": "error", "message": "无效的邮箱格式"}
            
            # 使用verify_code函数验证验证码
            is_valid, message = verify_code(identifier, code)
            if not is_valid:
                return {"status": "error", "message": message}
            
            # 创建或更新用户
            user = session.query(User).filter(User.email == identifier).first()
            
            if not user:
                user = User(email=identifier)
                session.add(user)
            
            user.is_verified = True
            session.commit()
            
            # 生成 JWT token
            token = jwt.encode(
                {
                    'user_id': user.id,
                    'exp': datetime.now(UTC) + timedelta(days=1)
                },
                os.getenv('JWT_SECRET', 'your-secret-key'),
                algorithm='HS256'
            )
            
            return {
                "status": "success",
                "message": "验证成功",
                "token": token
            }
            
        except Exception as e:
            session.rollback()
            print(f"Error in handle_verify_code: {str(e)}")  # 添加错误日志
            return {"status": "error", "message": str(e)}
        finally:
            session.close()

    def handle_login(self, data):
        session = Session()
        try:
            identifier = data.get('identifier')
            password = data.get('password')
            
            if not identifier or not password:
                return {"status": "error", "message": "缺少必要信息"}
            
            # 验证邮箱格式
            if not User.is_valid_email(identifier):
                return {"status": "error", "message": "无效的邮箱格式"}
            
            user = session.query(User).filter(User.email == identifier).first()
            
            # 修改登录验证逻辑：先检查用户是否存在，然后对非管理员检查是否验证
            if not user:
                return {"status": "error", "message": "邮箱不存在"}
            
            # 只有非管理员用户才需要验证 is_verified 状态
            if not user.is_admin and not user.is_verified:
                return {"status": "error", "message": "邮箱未验证"}
            
            if not user.check_password(password):
                return {"status": "error", "message": "密码错误"}
            
            # 检查用户是否是管理员（如果没有is_admin字段，默认为False）
            is_admin = getattr(user, 'is_admin', False)
            
            # 记录登录IP和时间
            client_ip = self.client_address[0]
            user.last_login_ip = client_ip
            user.last_login_time = datetime.now(UTC)
            session.commit()
            
            token = jwt.encode(
                {
                    'user_id': user.id,
                    'exp': datetime.now(UTC) + timedelta(days=1),
                    'is_admin': is_admin  # 添加管理员标识到JWT中
                },
                os.getenv('JWT_SECRET', 'your-secret-key'),
                algorithm='HS256'
            )
            
            return {
                "status": "success",
                "message": "登录成功",
                "token": token
            }
            
        except Exception as e:
            return {"status": "error", "message": str(e)}
        finally:
            session.close()

    def handle_register(self, data):
        session = Session()
        try:
            identifier = data.get('identifier')
            password = data.get('password')
            code = data.get('code')
            
            if not identifier or not password or not code:
                return {"status": "error", "message": "缺少必要信息"}
            
            # 验证邮箱格式
            if not User.is_valid_email(identifier):
                return {"status": "error", "message": "无效的邮箱格式"}
                
            # 验证验证码
            is_valid, message = verify_code(identifier, code)
            if not is_valid:
                return {"status": "error", "message": message}
            
            # 创建用户
            success, message = create_user(identifier, password)
            
            if success:
                return {"status": "success", "message": message}
            else:
                return {"status": "error", "message": message}
            
        except Exception as e:
            session.rollback()
            return {"status": "error", "message": str(e)}
        finally:
            session.close()

    def handle_change_password(self, data, user_id):
        session = Session()
        try:
            # 从用户ID查找用户
            user = session.query(User).filter(User.id == user_id).first()
            if not user:
                return {"status": "error", "message": "用户不存在"}
                
            new_password = data.get('newPassword')
            code = data.get('code')
            
            if not new_password or not code:
                return {"status": "error", "message": "缺少必要信息"}
            
            # 验证验证码
            is_valid, message = verify_code(user.email, code)
            if not is_valid:
                return {"status": "error", "message": message}
            
            # 修改密码
            user.set_password(new_password)
            session.commit()
            
            return {"status": "success", "message": "密码修改成功"}
            
        except Exception as e:
            session.rollback()
            print(f"修改密码失败: {str(e)}")
            return {"status": "error", "message": str(e)}
        finally:
            session.close()

    def send_email_code(self, email, code):
        """发送验证码邮件，使用Gmail SMTP服务器"""
        try:
            # 从模板文件读取HTML内容
            template_path = os.path.join(os.path.dirname(__file__), 'templates', 'email_verification.html')
            with open(template_path, 'r', encoding='utf-8') as file:
                template = file.read()
            
            # 替换模板中的验证码
            html_content = template.format(code=code)
            
            # 判断是否为测试环境（example.com域名的邮箱视为测试邮箱）
            is_test = email.endswith('example.com')
            
            if is_test:
                print(f"\n=== 测试模式：不实际发送邮件 ===")
                print(f"接收人: {email}")
                print(f"验证码: {code}")
                print(f"=== 测试邮件内容已打印到控制台 ===\n")
                return True
            
            # 创建MIMEText对象，指定HTML内容
            msg = MIMEText(html_content, 'html', 'utf-8')
            msg['Subject'] = '【Happy Work】您的验证码'
            msg['From'] = os.getenv('EMAIL_FROM')
            msg['To'] = email
            
            # 连接Gmail SMTP服务器并发送邮件
            with smtplib.SMTP_SSL(os.getenv('SMTP_SERVER'), int(os.getenv('SMTP_PORT'))) as server:
                server.login(os.getenv('EMAIL_USER'), os.getenv('EMAIL_PASSWORD'))
                server.send_message(msg)
                print(f"验证码邮件已发送至: {email}")
                
            return True
        except Exception as e:
            print(f"发送邮件失败: {str(e)}")
            raise Exception(f"发送验证码邮件失败: {str(e)}")

    def handle_chat_message(self, data):
        """处理聊天消息"""
        try:
            # 打印接收到的数据，用于调试
            print("=" * 80)
            print("[handle_chat_message] 接收到的数据:", data)
            print(f"[handle_chat_message] 前端传入的模式值: {data.get('mode')}")  # 打印前端传递的模式

            # 检查mode参数是否有效
            if 'mode' not in data:
                return {"status": "error", "message": "缺少mode参数，请选择对话模式：'simulation'(场景模拟)或'solution'(解决方案)"}
            
            if data['mode'] not in ['simulation', 'solution']:
                return {"status": "error", "message": "mode参数值无效，只能是'simulation'(场景模拟)或'solution'(解决方案)"}

            # 记录用户最终选择的模式，确保它被正确传递
            selected_mode = data['mode']
            print(f"[handle_chat_message] 用户选择的模式: {selected_mode}")

            # 检查是否是后续对话（有 chatId 和 message）
            if 'chatId' in data and 'message' in data:
                # 标准化处理聊天ID
                original_chat_id = data['chatId']
                chat_id = normalize_chat_id(original_chat_id)
                print(f"[handle_chat_message] 处理后续对话，原始聊天ID: {original_chat_id}, 标准化后: {chat_id}")
                
                # 获取聊天信息以确定正确的模式
                session = Session()
                try:
                    # 尝试查询聊天记录
                    chat = session.query(Chat).filter(Chat.id == chat_id).first()
                    print(f"[handle_chat_message] 查询结果(id={chat_id}): {chat}")
                    
                    if chat is None:
                        print(f"[handle_chat_message] 警告：找不到聊天ID为 {chat_id} 的记录")
                        # 直接查询最近创建的聊天，用于调试
                        recent_chat = session.query(Chat).order_by(Chat.created_at.desc()).first()
                        print(f"[handle_chat_message] 最近创建的聊天: {recent_chat.id if recent_chat else None}")
                        if recent_chat:
                            print(f"[handle_chat_message] 最近聊天标题: {recent_chat.title}")
                    
                    if chat and chat.title:
                        print(f"[handle_chat_message] 聊天标题: {chat.title}")
                        # 从聊天标题判断原始模式
                        if '[场景模拟]' in chat.title:
                            # 强制使用场景模拟模式，修复模式切换bug
                            selected_mode = 'simulation'
                            print(f"[handle_chat_message] 根据聊天标题，强制使用场景模拟模式: {selected_mode}")
                        elif '[解决方案]' in chat.title:
                            selected_mode = 'solution'
                            print(f"[handle_chat_message] 根据聊天标题，强制使用解决方案模式: {selected_mode}")
                        else:
                            print(f"[handle_chat_message] 警告：聊天标题 '{chat.title}' 不包含模式信息，使用默认模式")
                    else:
                        print(f"[handle_chat_message] 警告：聊天记录无标题，使用用户提供的模式: {selected_mode}")
                except Exception as e:
                    print(f"[handle_chat_message] 查询聊天记录时出错: {str(e)}")
                    import traceback
                    traceback.print_exc()
                finally:
                    session.close()
                
                # 构建后续对话的数据格式
                chat_data = {
                    'type': 'follow_up',
                    'message': data['message'],
                    'chatId': chat_id,
                    'mode': selected_mode  # 使用确定的模式
                }
                print(f"[handle_chat_message] 构建的chat_data: {chat_data}")  # 打印构建的数据
                print(f"[handle_chat_message] 后续对话的最终模式: {chat_data['mode']}")  # 添加明确的模式日志
            else:
                # 验证首次对话的必要字段
                required_fields = ['puaType', 'severity', 'perpetrator', 'description']
                for field in required_fields:
                    if field not in data:
                        return {"status": "error", "message": f"缺少必要字段: {field}"}
                chat_data = {
                    'type': 'initial',
                    'puaType': data['puaType'],
                    'severity': data['severity'],
                    'perpetrator': data['perpetrator'],
                    'description': data['description'],
                    'mode': selected_mode  # 使用用户选择的明确模式
                }
                print(f"[handle_chat_message] 构建的chat_data: {chat_data}")  # 打印构建的数据
                print(f"[handle_chat_message] 初始对话的模式: {chat_data['mode']}")  # 添加明确的模式日志
            
            # 生成回复
            response = generate_pua_response(chat_data)
            print(f"[handle_chat_message] AI响应状态: {response['status']}")
            print(f"[handle_chat_message] AI响应模式: {response.get('mode')}")
            
            if response['status'] == 'error':
                return response
                
            # 确保响应包含正确的模式
            response['mode'] = selected_mode
            print(f"[handle_chat_message] 最终返回的模式: {response['mode']}")
            print("=" * 80)
                
            return response
            
        except Exception as e:
            print(f"处理聊天消息时出错: {str(e)}")
            import traceback
            traceback.print_exc()  # 打印完整的错误栈
            return {"status": "error", "message": str(e)}

    def handle_admin_users(self):
        """获取所有用户列表，仅管理员可用"""
        session = Session()
        try:
            users = session.query(User).all()
            user_list = []
            
            for user in users:
                # 查询用户最新的问卷和报告信息
                latest_questionnaire = session.query(Questionnaire).filter(
                    Questionnaire.user_id == user.id
                ).order_by(Questionnaire.created_at.desc()).first()
                
                report_preview_link = None
                if latest_questionnaire and latest_questionnaire.has_report:
                    # 查询问卷对应的报告
                    response = session.query(QuestionnaireResponse).filter(
                        QuestionnaireResponse.questionnaire_id == latest_questionnaire.id
                    ).first()
                    if response:
                        report_preview_link = response.preview_link
                
                user_data = {
                    'id': user.id,
                    'email': user.email,
                    'phone': user.phone,
                    'is_verified': user.is_verified,
                    'created_at': user.created_at.isoformat() if user.created_at else None,
                    'is_admin': getattr(user, 'is_admin', False),
                    'last_login_ip': getattr(user, 'last_login_ip', '未知'),
                    'last_login_time': user.last_login_time.isoformat() if getattr(user, 'last_login_time', None) else '未知',
                    'is_paid': getattr(user, 'is_paid', False),
                    'has_report': True if report_preview_link else False,
                    'report_link': report_preview_link
                }
                user_list.append(user_data)
            
            # 添加一些统计信息
            stats = {
                'total': len(users),
                'verified': sum(1 for user in users if user.is_verified),
                'admins': sum(1 for user in users if getattr(user, 'is_admin', False)),
                'paid': sum(1 for user in users if getattr(user, 'is_paid', False)),
                'with_report': sum(1 for user in user_list if user['has_report'])
            }
            
            return {"status": "success", "users": user_list, "stats": stats}
        except Exception as e:
            logger.error(f"获取用户列表失败: {str(e)}")
            return {"status": "error", "message": str(e)}
        finally:
            session.close()

    def handle_admin_chats(self):
        """获取所有聊天记录，仅管理员可用"""
        session = Session()
        try:
            chats = session.query(Chat).all()
            chat_list = [{
                'id': chat.id,
                'user_id': chat.user_id,
                'title': chat.title,
                'created_at': chat.created_at.isoformat() if chat.created_at else None,
                'last_activity': chat.last_activity.isoformat() if chat.last_activity else None,
                'message_count': len(chat.messages)
            } for chat in chats]
            
            # 添加一些统计信息
            now = datetime.now(UTC)
            stats = {
                'total_chats': len(chats),
                'total_messages': sum(len(chat.messages) for chat in chats),
                'active_today': sum(1 for chat in chats if chat.last_activity and 
                                  chat.last_activity.tzinfo and 
                                  (now - chat.last_activity).days < 1)
            }
            
            return {"status": "success", "chats": chat_list, "stats": stats}
        except Exception as e:
            logger.error(f"获取聊天列表失败: {str(e)}")
            return {"status": "error", "message": str(e)}
        finally:
            session.close()
            
    def handle_admin_stats(self):
        """获取系统统计信息，仅管理员可用"""
        session = Session()
        try:
            # 用户统计
            total_users = session.query(User).count()
            verified_users = session.query(User).filter(User.is_verified == True).count()
            
            # 聊天统计
            total_chats = session.query(Chat).count()
            total_messages = session.query(Message).count()
            
            # 今日活跃统计
            today = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
            
            # 使用更安全的方法计算活跃用户
            active_users_today = 0
            new_chats_today = 0
            new_messages_today = 0
            
            try:
                # 获取今日活跃用户数
                active_chats = session.query(Chat).all()
                active_users_set = set()
                for chat in active_chats:
                    if chat.last_activity and chat.last_activity.tzinfo:
                        time_diff = datetime.now(UTC) - chat.last_activity
                        if time_diff.days < 1:
                            active_users_set.add(chat.user_id)
                active_users_today = len(active_users_set)
                
                # 获取今日新增聊天数
                new_chats = session.query(Chat).all()
                new_chats_today = sum(1 for chat in new_chats 
                                    if chat.created_at and chat.created_at.tzinfo 
                                    and chat.created_at >= today)
                
                # 获取今日新增消息数
                new_messages = session.query(Message).all()
                new_messages_today = sum(1 for msg in new_messages 
                                       if msg.created_at and msg.created_at.tzinfo 
                                       and msg.created_at >= today)
                
            except Exception as e:
                logger.error(f"计算今日统计数据时出错: {str(e)}")
                # 继续执行，返回已有的统计信息
            
            stats = {
                "users": {
                    "total": total_users,
                    "verified": verified_users
                },
                "chats": {
                    "total": total_chats,
                    "total_messages": total_messages
                },
                "today": {
                    "active_users": active_users_today,
                    "new_chats": new_chats_today,
                    "new_messages": new_messages_today
                }
            }
            
            return {"status": "success", "stats": stats}
        except Exception as e:
            logger.error(f"获取统计信息失败: {str(e)}")
            return {"status": "error", "message": str(e)}
        finally:
            session.close()

    def handle_admin_chat_details(self, chat_id):
        """获取聊天详细内容，仅管理员可用"""
        session = Session()
        try:
            # 获取聊天记录
            chat = session.query(Chat).filter(Chat.id == chat_id).first()
            
            if not chat:
                return {"status": "error", "message": "找不到该聊天记录"}
            
            # 获取用户信息
            user = session.query(User).filter(User.id == chat.user_id).first()
            user_info = {
                'id': user.id,
                'email': user.email,
                'phone': user.phone if user.phone else '-',
                'last_login_ip': user.last_login_ip or '未知',
                'last_login_time': user.last_login_time.isoformat() if user.last_login_time else '未知',
                'created_at': user.created_at.isoformat() if user.created_at else '未知'
            } if user else {'id': '未知', 'email': '未知', 'phone': '未知', 'last_login_ip': '未知', 'last_login_time': '未知'}
            
            # 获取聊天信息
            chat_info = {
                'id': chat.id,
                'title': chat.title,
                'created_at': chat.created_at.isoformat() if chat.created_at else None,
                'last_activity': chat.last_activity.isoformat() if chat.last_activity else None
            }
            
            # 获取所有消息
            messages = []
            for message in chat.messages:
                messages.append({
                    'id': message.id,
                    'role': message.role,
                    'content': message.content,
                    'form_data': message.form_data,
                    'timestamp': message.created_at.isoformat() if message.created_at else None
                })
            
            return {
                "status": "success", 
                "data": {
                    "chat": chat_info,
                    "user": user_info,
                    "messages": messages
                }
            }
        except Exception as e:
            logger.error(f"获取聊天详情失败: {str(e)}")
            return {"status": "error", "message": str(e)}
        finally:
            session.close()

    def handle_admin_delete_chat(self, chat_id):
        session = Session()
        try:
            chat_id = int(chat_id)
            # 先删除与该聊天相关的所有消息
            session.query(Message).filter(Message.chat_id == chat_id).delete()
            # 然后删除聊天本身
            chat = session.query(Chat).filter(Chat.id == chat_id).first()
            if chat:
                session.delete(chat)
                session.commit()
                logger.info(f"管理员删除了聊天记录: ID {chat_id}")
                return {"status": "success", "message": f"聊天记录 {chat_id} 已删除"}
            else:
                logger.warning(f"尝试删除不存在的聊天记录: ID {chat_id}")
                return {"status": "error", "message": "聊天记录未找到"}
        except ValueError:
            logger.error(f"无效的聊天ID格式: {chat_id}")
            return {"status": "error", "message": "无效的聊天ID"}
        except Exception as e:
            session.rollback()
            logger.error(f"删除聊天记录时出错 (ID: {chat_id}): {e}", exc_info=True)
            return {"status": "error", "message": f"删除聊天记录时出错: {e}"}
        finally:
            session.close()

    def handle_admin_clear_all_chats(self):
        """清除所有聊天记录，仅管理员可用"""
        session = Session()
        try:
            # 删除所有消息
            message_count = session.query(Message).delete()
            
            # 删除所有聊天
            chat_count = session.query(Chat).delete()
            
            session.commit()
            
            return {
                "status": "success", 
                "message": f"已成功清除所有聊天记录",
                "data": {
                    "chats_deleted": chat_count,
                    "messages_deleted": message_count
                }
            }
        except Exception as e:
            session.rollback()
            logger.error(f"清除所有聊天记录失败: {str(e)}")
            return {"status": "error", "message": str(e)}
        finally:
            session.close()

    def handle_add_admin(self, data):
        session = Session()
        try:
            email = data.get('email')
            add_type = data.get('add_type') # 'existing' or 'new'
            password = data.get('password')

            if not email or not User.is_valid_email(email):
                return {"status": "error", "message": "无效的邮箱地址"}
            if not add_type or add_type not in ['existing', 'new']:
                return {"status": "error", "message": "无效的操作类型"}

            user = session.query(User).filter(User.email == email).first()

            if add_type == 'existing':
                if user:
                    if user.is_admin:
                        return {"status": "warning", "message": "该用户已经是管理员"}
                    user.is_admin = True
                    session.commit()
                    logger.info(f"管理员添加了现有用户 {email} 为管理员")
                    return {"status": "success", "message": f"用户 {email} 已被设为管理员"}
                else:
                    return {"status": "error", "message": "邮箱未注册，无法直接添加为管理员"}
            
            elif add_type == 'new':
                if user:
                    return {"status": "error", "message": "该邮箱已被注册"}
                if not password or len(password) < 6: # 简单的密码长度检查
                    return {"status": "error", "message": "新管理员必须设置至少6位密码"}
                
                new_admin = User(email=email, is_admin=True, is_verified=False) # 创建用户，设为管理员，但不设为已验证
                new_admin.set_password(password) # 设置密码
                session.add(new_admin)
                session.commit()
                logger.info(f"管理员创建了新的管理员账户: {email}")
                return {"status": "success", "message": f"管理员账户 {email} 创建成功"}

        except Exception as e:
            session.rollback()
            logger.error(f"添加管理员时出错: {e}", exc_info=True)
            return {"status": "error", "message": f"处理请求时发生内部错误: {e}"}
        finally:
            session.close()

    def handle_admin_delete_user(self, requesting_admin_id, user_id_to_delete):
        """
        处理管理员删除用户的请求
        
        Args:
            requesting_admin_id: 发起请求的管理员ID
            user_id_to_delete: 要删除的用户ID
        
        Returns:
            操作结果信息
        """
        session = Session()
        try:
            # 检查要删除的用户是否存在
            user_to_delete = session.query(User).filter(User.id == user_id_to_delete).first()
            if not user_to_delete:
                return {"status": "error", "message": "用户不存在"}
                
            # 检查要删除的用户是否是管理员
            if user_to_delete.is_admin:
                # 不允许删除管理员
                return {"status": "error", "message": "不能删除管理员账户"}
            
            # 处理删除用户的相关聊天记录
            chats = session.query(Chat).filter(Chat.user_id == user_id_to_delete).all()
            for chat in chats:
                # 删除与聊天相关的所有消息
                session.query(Message).filter(Message.chat_id == chat.id).delete()
                
            # 删除用户的所有聊天
            session.query(Chat).filter(Chat.user_id == user_id_to_delete).delete()
            
            # 删除用户的验证码记录
            session.query(VerificationCode).filter(
                (VerificationCode.identifier == user_to_delete.email) | 
                (VerificationCode.identifier == user_to_delete.phone)
            ).delete()
            
            # 删除用户本身
            session.delete(user_to_delete)
            session.commit()
            
            return {"status": "success", "message": "用户删除成功"}
        except Exception as e:
            session.rollback()
            logger.error(f"删除用户时出错: {str(e)}")
            return {"status": "error", "message": f"删除用户时出错: {str(e)}"}
        finally:
            session.close()
    
    def handle_questionnaire_submit(self, user_id, data):
        """
        处理问卷提交请求
        
        Args:
            user_id: 用户ID
            data: 问卷数据，包含每个问题的答案
            
        Returns:
            包含状态信息的字典
        """
        try:
            # 检查数据格式
            if not isinstance(data, dict) or 'answers' not in data:
                return {
                    "status": "error",
                    "message": "无效的问卷数据格式"
                }
                
            answers_data = data['answers']
            
            # 添加用户ID到问卷数据中，用于更新用户has_pdf字段
            answers_data['user_id'] = user_id
                
            # 保存问卷数据到数据库
            save_result = save_questionnaire(user_id, answers_data)
            if save_result['status'] == 'error':
                return save_result
                
            questionnaire_id = save_result['questionnaire_id']
            
            # 生成报告
            report_result = generate_questionnaire_report(answers_data)
            if report_result['status'] == 'error':
                return report_result
                
            # 保存报告响应
            save_response_result = save_questionnaire_response(
                questionnaire_id, 
                report_result['report'], 
                report_result['preview_link']
            )
            if save_response_result['status'] == 'error':
                return save_response_result
                
            # 返回成功信息
            return {
                "status": "success",
                "message": "问卷提交成功，报告已生成",
                "preview_link": report_result['preview_link']
            }
        except Exception as e:
            logger.error(f"处理问卷提交请求时出错: {str(e)}")
            return {
                "status": "error",
                "message": f"处理问卷提交请求时出错: {str(e)}"
            }
    
    def handle_get_user_questionnaires(self, user_id):
        """
        获取用户的问卷列表
        
        Args:
            user_id: 用户ID
            
        Returns:
            包含问卷列表的字典
        """
        try:
            session = Session()
            try:
                # 查询用户的所有问卷，按创建时间倒序排列
                questionnaires = session.query(Questionnaire).filter(
                    Questionnaire.user_id == user_id
                ).order_by(Questionnaire.created_at.desc()).all()
                
                # 获取token
                auth_header = self.headers.get('Authorization')
                token = None
                if auth_header and auth_header.startswith('Bearer '):
                    token = auth_header.split(' ')[1]
                
                # 格式化问卷数据
                formatted_questionnaires = []
                for questionnaire in questionnaires:
                    # 查询问卷对应的报告响应
                    response = session.query(QuestionnaireResponse).filter(
                        QuestionnaireResponse.questionnaire_id == questionnaire.id
                    ).first()
                    
                    # 处理预览链接，添加token参数
                    preview_link = None
                    if response and response.preview_link:
                        preview_link = response.preview_link
                        # 如果有token，则添加到预览链接中
                        if token:
                            preview_link = f"{preview_link}?token={token}"
                    
                    formatted_questionnaires.append({
                        "id": questionnaire.id,
                        "created_at": questionnaire.created_at.isoformat(),
                        "has_report": questionnaire.has_report,
                        "preview_link": preview_link
                    })
                
                return {
                    "status": "success",
                    "questionnaires": formatted_questionnaires
                }
            except Exception as e:
                logger.error(f"查询用户问卷列表失败: {str(e)}")
                return {
                    "status": "error",
                    "message": f"查询用户问卷列表失败: {str(e)}"
                }
            finally:
                session.close()
        except Exception as e:
            logger.error(f"处理获取用户问卷列表请求时出错: {str(e)}")
            return {
                "status": "error",
                "message": f"处理获取用户问卷列表请求时出错: {str(e)}"
            }
    
    def handle_preview_report(self, preview_id):
        """
        处理报告预览请求
        
        Args:
            preview_id: 预览ID
            
        Returns:
            包含报告内容的字典
        """
        try:
            print(f"处理预览报告请求，预览ID: {preview_id}")
            # 从数据库中查找对应的报告
            session = Session()
            try:
                # 更精确的查询，采用SQL LIKE语句直接找到匹配的报告
                print("开始查询问卷响应数据")
                query = session.query(QuestionnaireResponse).filter(
                    QuestionnaireResponse.preview_link.like(f"%{preview_id}%")
                )
                responses = query.all()
                print(f"找到 {len(responses)} 条匹配预览ID的问卷响应记录")
                
                # 调试: 打印所有response的preview_link
                for idx, response in enumerate(responses):
                    print(f"Response #{idx+1}, ID: {response.id}, Preview Link: {response.preview_link}")
                
                # 如果没有通过LIKE查询找到，则尝试加载所有记录进行精确匹配
                if not responses:
                    print(f"通过SQL LIKE未找到匹配，尝试加载所有记录进行精确匹配")
                    all_responses = session.query(QuestionnaireResponse).all()
                    print(f"总共有 {len(all_responses)} 条问卷响应记录")
                    
                    # 手动筛选匹配预览ID的记录
                    matching_responses = []
                    for resp in all_responses:
                        if resp.preview_link and preview_id in resp.preview_link:
                            matching_responses.append(resp)
                            print(f"手动匹配找到记录: ID={resp.id}, PreviewLink={resp.preview_link}")
                    
                    responses = matching_responses
                    print(f"手动筛选后找到 {len(responses)} 条匹配的记录")
                
                if not responses:
                    print(f"未找到匹配 '{preview_id}' 的报告")
                    return {
                        "status": "error",
                        "message": "未找到对应的报告"
                    }
                
                # 使用找到的第一条匹配记录
                found_response = responses[0]
                print(f"使用匹配的响应，ID: {found_response.id}")
                
                # 获取关联的问卷
                questionnaire = session.query(Questionnaire).filter(
                    Questionnaire.id == found_response.questionnaire_id
                ).first()
                
                if questionnaire:
                    print(f"找到关联问卷，ID: {questionnaire.id}")
                else:
                    print("未找到关联问卷")
                
                # 获取用户信息
                user = None
                if questionnaire:
                    user = session.query(User).filter(
                        User.id == questionnaire.user_id
                    ).first()
                    
                    if user:
                        print(f"找到关联用户，ID: {user.id}, Email: {user.email}")
                    else:
                        print("未找到关联用户")
                
                # 返回报告内容
                content_length = len(found_response.response_content) if found_response.response_content else 0
                print(f"返回报告，内容长度: {content_length}")
                
                # 检查内容格式
                if content_length > 0:
                    content_sample = (found_response.response_content[:100] + '...') if content_length > 100 else found_response.response_content
                    print(f"报告内容示例: {content_sample}")
                else:
                    print("警告: 报告内容为空")
                
                return {
                    "status": "success",
                    "report": found_response.response_content or "",
                    "created_at": found_response.created_at.isoformat() if found_response.created_at else None,
                    "user_info": {
                        "email": user.email if user else None
                    } if user else None
                }
            except Exception as e:
                logger.error(f"查询报告时出错: {str(e)}")
                print(f"查询报告时出错: {str(e)}")
                import traceback
                traceback.print_exc()
                return {
                    "status": "error",
                    "message": f"查询报告时出错: {str(e)}"
                }
            finally:
                session.close()
        except Exception as e:
            logger.error(f"处理报告预览请求时出错: {str(e)}")
            print(f"处理报告预览请求时出错: {str(e)}")
            import traceback
            traceback.print_exc()
            return {
                "status": "error",
                "message": f"处理报告预览请求时出错: {str(e)}"
            }

def verify_code(identifier, code):
    """验证短信验证码"""
    session = Session()
    try:
        # 使用SQLAlchemy ORM获取验证码记录
        verification = session.query(VerificationCode).filter(
            VerificationCode.identifier == identifier,
            VerificationCode.code == code,  # 直接匹配验证码
            VerificationCode.is_used == False
        ).order_by(VerificationCode.created_at.desc()).first()
        
        if not verification:
            return False, "验证码错误或已使用"
            
        # 标记验证码为已使用
        verification.is_used = True
        session.commit()
            
        return True, "验证成功"
        
    except Exception as e:
        session.rollback()
        print(f"验证码验证失败: {str(e)}")
        return False, f"验证失败: {str(e)}"
    finally:
        session.close()

def create_user(identifier, password):
    """创建新用户"""
    session = Session()
    try:
        # 验证邮箱格式
        if not User.is_valid_email(identifier):
            return False, "无效的邮箱格式"
            
        # 检查用户是否已存在
        existing_user = session.query(User).filter(User.email == identifier).first()
        if existing_user:
            return False, "该邮箱已注册"
            
        # 创建新用户
        new_user = User(email=identifier, is_verified=True)
        new_user.set_password(password)
        
        session.add(new_user)
        session.commit()
        
        return True, "注册成功"
        
    except Exception as e:
        session.rollback()
        print(f"创建用户失败: {str(e)}")
        return False, f"注册失败: {str(e)}"
    finally:
        session.close()

def cleanup_task(interval_hours=24, chat_retention_days=30):
    """
    定期运行清理任务的后台线程函数
    
    参数:
        interval_hours (int): 清理任务的间隔小时数，默认24小时
        chat_retention_days (int): 聊天记录保留天数，默认30天
    """
    logger.info(f"聊天记录清理任务已启动 - 保留{chat_retention_days}天内的聊天，每{interval_hours}小时清理一次")
    
    while True:
        try:
            # 执行清理任务
            logger.info("开始执行定期清理任务...")
            cleanup_old_chats(days=chat_retention_days)
            logger.info(f"清理任务完成，将在{interval_hours}小时后再次执行")
            
            # 等待指定间隔时间
            time.sleep(interval_hours * 3600)  # 转换为秒
        except Exception as e:
            logger.error(f"清理任务执行出错: {str(e)}")
            # 即使出错也等待一段时间后重试
            time.sleep(3600)  # 出错后等待1小时再重试

def run(server_class=HTTPServer, handler_class=AuthHandler, port=8000, enable_cleanup=True,
         cleanup_interval=24, retention_days=30):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    
    # 启动清理后台线程
    if enable_cleanup:
        cleanup_thread = threading.Thread(
            target=cleanup_task,
            args=(cleanup_interval, retention_days),
            daemon=True  # 设为守护线程，主程序结束时自动结束
        )
        cleanup_thread.start()
        logger.info(f"聊天记录自动清理线程已启动（保留{retention_days}天，间隔{cleanup_interval}小时）")
    
    logger.info(f'Starting server on port {port}...')
    httpd.serve_forever()

def normalize_chat_id(chat_id_input):
    """标准化聊天ID，处理字符串和数字格式"""
    try:
        # 如果是字符串且是数字形式，转换为整数
        if isinstance(chat_id_input, str) and chat_id_input.isdigit():
            chat_id = int(chat_id_input)
            # 如果是13位时间戳，前端可能使用时间戳作为ID
            if len(chat_id_input) >= 13:
                print(f"检测到可能是时间戳形式的ID: {chat_id_input}")
                # 查询数据库获取真实ID
                session = Session()
                try:
                    # 查询最近的聊天，可能是用户刚刚创建的
                    recent_chat = session.query(Chat).order_by(Chat.created_at.desc()).first()
                    if recent_chat:
                        print(f"使用最近创建的聊天ID: {recent_chat.id} 替代时间戳: {chat_id_input}")
                        return recent_chat.id
                except Exception as e:
                    print(f"查询最近聊天时出错: {str(e)}")
                finally:
                    session.close()
            return chat_id
        # 否则保持原格式
        return chat_id_input
    except Exception as e:
        print(f"标准化聊天ID时出错: {str(e)}")
        # 出错时返回原始值
        return chat_id_input

if __name__ == '__main__':
    # 从环境变量获取配置参数
    cleanup_enabled = os.getenv('ENABLE_CHAT_CLEANUP', 'true').lower() == 'true'
    cleanup_interval = int(os.getenv('CHAT_CLEANUP_INTERVAL_HOURS', '24'))
    retention_days = int(os.getenv('CHAT_RETENTION_DAYS', '30'))
    
    run(
        port=int(os.getenv('PORT', '8000')),
        enable_cleanup=cleanup_enabled,
        cleanup_interval=cleanup_interval,
        retention_days=retention_days
    )