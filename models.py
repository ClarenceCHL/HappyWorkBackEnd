from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, ForeignKey, JSON, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
import re
import random
import string
from datetime import datetime, timedelta, UTC
from werkzeug.security import generate_password_hash, check_password_hash
import os
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()

Base = declarative_base()

# 根据环境变量选择数据库
ENV = os.getenv('FLASK_ENV', 'production')
if ENV == 'development':
    db_path = 'dev_users.db'
    print("使用开发环境数据库: dev_users.db")
else:
    db_path = 'users.db'
    print("使用生产环境数据库: users.db")

engine = create_engine(f'sqlite:///{db_path}')

class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    email = Column(String(120), unique=True)
    phone = Column(String(20), unique=True)
    password_hash = Column(String(128))
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    is_admin = Column(Boolean, default=False)  # 添加管理员标识字段
    last_login_ip = Column(String(50), nullable=True)  # 添加最后登录IP
    last_login_time = Column(DateTime(timezone=True), nullable=True)  # 最后登录时间
    is_paid = Column(Boolean, default=False, nullable=False) # 新增：用户是否已支付
    has_pdf = Column(Boolean, default=False, nullable=False) # 新增：是否已生成PDF
    pdf_storage_path = Column(String, nullable=True)        # 新增：PDF存储路径或标识符
    
    # 添加与Chat的关系
    chats = relationship("Chat", back_populates="user")
    # 添加与Questionnaire的关系
    questionnaires = relationship("Questionnaire", back_populates="user")
    
    @staticmethod
    def is_valid_email(email):
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    @staticmethod
    def is_valid_phone(phone):
        pattern = r'^1[3-9]\d{9}$'  # 中国手机号格式
        return re.match(pattern, phone) is not None

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class VerificationCode(Base):
    __tablename__ = 'verification_codes'
    
    id = Column(Integer, primary_key=True)
    identifier = Column(String(120), nullable=False)  # 邮箱或手机号
    code = Column(String(6), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)
    is_used = Column(Boolean, default=False)
    
    @staticmethod
    def generate_code():
        return ''.join(random.choices(string.digits, k=6))
    
    @staticmethod
    def is_expired(expires_at):
        # 暂时禁用过期检查，直接返回False
        return False

class Chat(Base):
    __tablename__ = 'chats'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    title = Column(String(200))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_activity = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    
    # 关系
    user = relationship("User", back_populates="chats")
    messages = relationship("Message", back_populates="chat", order_by="Message.created_at")

class Message(Base):
    __tablename__ = 'messages'
    
    id = Column(Integer, primary_key=True)
    chat_id = Column(Integer, ForeignKey('chats.id'))  # 修正字段名为chat_id
    role = Column(String(20))  # 'user' 或 'assistant'
    content = Column(String)
    form_data = Column(String, nullable=True)  # 存储表单数据的JSON字符串
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # 关系
    chat = relationship("Chat", back_populates="messages")

class Questionnaire(Base):
    __tablename__ = 'questionnaires'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    answers = Column(Text, nullable=False)  # 存储问卷答案的JSON字符串
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    has_report = Column(Boolean, default=False)  # 是否已生成报告
    
    # 关系
    user = relationship("User", back_populates="questionnaires")
    responses = relationship("QuestionnaireResponse", back_populates="questionnaire")

class QuestionnaireResponse(Base):
    __tablename__ = 'questionnaire_responses'
    
    id = Column(Integer, primary_key=True)
    questionnaire_id = Column(Integer, ForeignKey('questionnaires.id'))
    response_content = Column(Text, nullable=False)  # 存储AI回复的JSON字符串
    preview_link = Column(String(255), nullable=True)  # 预览链接
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # 关系
    questionnaire = relationship("Questionnaire", back_populates="responses")

Base.metadata.create_all(engine)
