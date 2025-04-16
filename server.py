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
                    
                    # 添加调试日志
                    print("=" * 80)
                    print(f"[/chat/follow_up] 处理后续对话，用户ID: {user_id}")
                    print(f"[/chat/follow_up] 接收到的完整数据: {data}")
                    print(f"[/chat/follow_up] 前端传入的Mode参数: {data.get('mode')}")
                    
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
                    logger.info(f"后续对话使用模式: {selected_mode}")
                    print(f"[/chat/follow_up] 初始模式: {selected_mode}")
                    
                    # 获取聊天ID
                    original_chat_id = data.get('chatId')
                    if not original_chat_id:
                        response = {"status": "error", "message": "缺少聊天ID"}
                        self.wfile.write(json.dumps(response).encode('utf-8'))
                        return
                    
                    # 标准化处理聊天ID
                    chat_id = normalize_chat_id(original_chat_id)
                    print(f"[/chat/follow_up] 原始聊天ID: {original_chat_id}, 标准化后: {chat_id}")
                    
                    # 获取聊天信息以确定正确的模式
                    session = Session()
                    try:
                        # 尝试查询聊天记录
                        chat = session.query(Chat).filter(Chat.id == chat_id).first()
                        print(f"[/chat/follow_up] 查询结果(id={chat_id}): {chat}")
                        
                        if chat is None:
                            print(f"[/chat/follow_up] 警告：找不到聊天ID为 {chat_id} 的记录")
                            # 直接查询最近创建的聊天，用于调试
                            recent_chat = session.query(Chat).order_by(Chat.created_at.desc()).first()
                            print(f"[/chat/follow_up] 最近创建的聊天: {recent_chat.id if recent_chat else None}")
                            if recent_chat:
                                print(f"[/chat/follow_up] 最近聊天标题: {recent_chat.title}")
                        
                        if chat and chat.title:
                            print(f"[/chat/follow_up] 聊天标题: {chat.title}")
                            # 从聊天标题判断原始模式
                            if '[场景模拟]' in chat.title:
                                # 强制使用场景模拟模式，修复模式切换bug
                                selected_mode = 'simulation'
                                print(f"[/chat/follow_up] 根据聊天标题，强制使用场景模拟模式: {selected_mode}")
                            elif '[解决方案]' in chat.title:
                                selected_mode = 'solution'
                                print(f"[/chat/follow_up] 根据聊天标题，强制使用解决方案模式: {selected_mode}")
                            else:
                                print(f"[/chat/follow_up] 警告：聊天标题 '{chat.title}' 不包含模式信息，使用默认模式")
                        else:
                            print(f"[/chat/follow_up] 警告：聊天记录无标题，使用用户提供的模式: {selected_mode}")
                    except Exception as e:
                        print(f"[/chat/follow_up] 查询聊天记录时出错: {str(e)}")
                        import traceback
                        traceback.print_exc()
                    finally:
                        session.close()
                    
                    # 构建对话数据，确保mode参数正确传递
                    chat_data = {
                        'type': 'follow_up',
                        'message': data.get('message', ''),
                        'chatId': chat_id,
                        'mode': selected_mode  # 使用确定的模式
                    }
                    print(f"[/chat/follow_up] 构建的chat_data: {chat_data}")  # 打印构建的数据
                    print(f"[/chat/follow_up] 最终使用的模式: {selected_mode}")  # 添加明确的模式日志
                    
                    # 生成回复
                    ai_response = generate_pua_response(chat_data)
                    logger.info(f"AI响应: {ai_response}")  # 添加日志
                    print(f"[/chat/follow_up] AI响应模式: {ai_response.get('mode')}")
                    
                    # 如果生成成功，保存消息记录
                    if ai_response['status'] == 'success':
                        session = Session()
                        try:
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
                                "mode": selected_mode  # 将用户选择的模式返回给前端
                            }
                            print(f"[/chat/follow_up] 返回给前端的模式: {response['mode']}")
                            print("=" * 80)
                        except Exception as e:
                            session.rollback()
                            print("保存消息失败:", str(e))  # 添加错误日志
                            response = {"status": "error", "message": f"保存消息失败: {str(e)}"}
                        finally:
                            session.close()
                    else:
                        print("AI生成失败:", ai_response)  # 添加错误日志
                        # 确保错误响应也包含正确的模式
                        if 'mode' not in ai_response:
                            ai_response['mode'] = selected_mode
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