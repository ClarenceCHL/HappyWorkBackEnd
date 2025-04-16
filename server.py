from http.server import HTTPServer, BaseHTTPRequestHandler
import json
from sqlalchemy.orm import sessionmaker
from models import engine, User, VerificationCode, Chat, Message
import jwt
from datetime import datetime, timedelta, UTC
import smtplib
from email.mime.text import MIMEText
import os
from dotenv import load_dotenv
from ai_service import generate_pua_response
from werkzeug.security import generate_password_hash
import sqlite3
import threading
import time
from cleanup_chats import cleanup_old_chats
import logging

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
    allowed_origins = os.getenv('ALLOWED_ORIGINS', 'http://localhost:5173,https://main.d2xmmf7vqo14pz.amplifyapp.com')
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
            self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
            self.send_header('Access-Control-Max-Age', '86400')
        
        self.end_headers()

    def do_OPTIONS(self):
        self._set_response_headers()
        self.wfile.write(b'')

    def do_GET(self):
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
            
            # 检查是否是获取用户信息的请求
            if self.path == '/user/info':
                response = self.handle_get_user_info(user_id)
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
            response = {"status": "error", "message": str(e)}
            
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
                    print("-" * 50)
                    print(f"处理聊天消息，用户ID: {user_id}")
                    print(f"接收到的完整数据: {data}")
                    print(f"Mode参数: {data['mode']}")
                    
                    # 直接调用handle_chat_message处理
                    ai_response = self.handle_chat_message(data)
                    print(f"AI响应: {ai_response}")
                    
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
                                "mode": data['mode']  # 将选择的模式返回给前端
                            }
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
                    response = {"status": "error", "message": str(e)}
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
                    
                    # 生成回复
                    ai_response = generate_pua_response(data)
                    print("AI响应:", ai_response)  # 添加日志
                    
                    # 如果生成成功，保存消息记录
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
                            
                            # 修改响应格式
                            response = {
                                "status": "success",
                                "advice": ai_response['advice'],
                                "mode": data['mode']  # 将选择的模式返回给前端
                            }
                        except Exception as e:
                            session.rollback()
                            print("保存消息失败:", str(e))  # 添加错误日志
                            response = {"status": "error", "message": f"保存消息失败: {str(e)}"}
                        finally:
                            session.close()
                    else:
                        print("AI生成失败:", ai_response)  # 添加错误日志
                        response = ai_response
                except jwt.ExpiredSignatureError:
                    response = {"status": "error", "message": "登录已过期"}
                except jwt.InvalidTokenError:
                    response = {"status": "error", "message": "无效的认证信息"}
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
                    
                    # 生成回复
                    ai_response = generate_pua_response(data)
                    
                    # 如果生成成功，保存对话记录
                    if ai_response['status'] == 'success':
                        session = Session()
                        try:
                            # 创建新的聊天，将mode保存到标题中以便前端显示
                            mode_text = "场景模拟" if data['mode'] == 'simulation' else "解决方案"
                            title_prefix = f"[{mode_text}] "
                            chat = Chat(
                                user_id=user_id,
                                title=title_prefix + (', '.join(data.get('puaType', [])) if 'puaType' in data else '新对话')
                            )
                            session.add(chat)
                            session.flush()  # 获取chat.id
                            
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
                            response = {
                                "status": "success",
                                "advice": ai_response['advice'],
                                "mode": data['mode'],  # 返回选择的模式给前端
                                "chatId": chat.id  # 添加chatId返回给前端
                            }
                            
                        except Exception as e:
                            session.rollback()
                            response = {"status": "error", "message": f"保存对话失败: {str(e)}"}
                        finally:
                            session.close()
                    else:
                        response = ai_response
                        
                except jwt.ExpiredSignatureError:
                    response = {"status": "error", "message": "登录已过期"}
                except jwt.InvalidTokenError:
                    response = {"status": "error", "message": "无效的认证信息"}
        else:
            response = {"status": "error", "message": "Invalid endpoint"}
        
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
            
            return {
                "status": "success",
                "email": user.email
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
            
            if not user or not user.is_verified:
                return {"status": "error", "message": "邮箱不存在或未验证"}
            
            if not user.check_password(password):
                return {"status": "error", "message": "密码错误"}
            
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
            print("接收到的数据:", data)
            print(f"前端传入的模式值: {data.get('mode')}")  # 打印前端传递的模式

            # 检查mode参数是否有效
            if 'mode' not in data:
                return {"status": "error", "message": "缺少mode参数，请选择对话模式：'simulation'(场景模拟)或'solution'(解决方案)"}
            
            if data['mode'] not in ['simulation', 'solution']:
                return {"status": "error", "message": "mode参数值无效，只能是'simulation'(场景模拟)或'solution'(解决方案)"}

            # 检查是否是后续对话（有 chatId 和 message）
            if 'chatId' in data and 'message' in data:
                # 构建后续对话的数据格式
                chat_data = {
                    'type': 'follow_up',
                    'message': data['message'],
                    'chatId': data['chatId'],
                    'mode': data['mode']  # 使用传入的明确模式
                }
                print(f"构建的chat_data: {chat_data}")  # 打印构建的数据
                print(f"后续对话的模式: {chat_data['mode']}")  # 添加明确的模式日志
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
                    'mode': data['mode']  # 使用传入的明确模式
                }
                print(f"构建的chat_data: {chat_data}")  # 打印构建的数据
                print(f"初始对话的模式: {chat_data['mode']}")  # 添加明确的模式日志
            
            # 生成回复
            response = generate_pua_response(chat_data)
            
            if response['status'] == 'error':
                return response
                
            # 确保响应包含正确的模式
            response['mode'] = data['mode']
                
            return response
            
        except Exception as e:
            print(f"处理聊天消息时出错: {str(e)}")
            import traceback
            traceback.print_exc()  # 打印完整的错误栈
            return {"status": "error", "message": str(e)}

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