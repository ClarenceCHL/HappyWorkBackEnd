import argparse
import os
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
# 不直接从 models 导入 Base 和 User，避免循环导入或过早初始化 engine
# from models import User, Base
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()

# 根据环境变量选择数据库
ENV = os.getenv('FLASK_ENV', 'production')
# 获取脚本所在的 backend 目录
backend_dir = os.path.dirname(os.path.abspath(__file__))

if ENV == 'development':
    db_name = 'dev_users.db'
    print("使用开发环境数据库: dev_users.db")
else:
    db_name = 'users.db'
    print("使用生产环境数据库: users.db")

# 数据库文件路径（在 backend/ 目录下）
db_path = os.path.join(backend_dir, db_name)
DATABASE_URL = f'sqlite:///{db_path}'

# 数据库连接
engine = create_engine(DATABASE_URL)

# --- 在 engine 创建之后，再导入 models ---
from models import User, Base
# --- 结束 ---

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def create_admin_user(email, password):
    """创建管理员用户"""
    db = SessionLocal()
    try:
        # 检查用户是否已存在
        existing_user = db.query(User).filter(User.email == email).first()
        if existing_user:
            print(f"错误: 邮箱 '{email}' 已被注册。")
            # 可以选择更新现有用户为管理员，但根据请求是创建，所以这里只提示
            # if not existing_user.is_admin:
            #     existing_user.is_admin = True
            #     db.commit()
            #     print(f"用户 '{email}' 已存在，已将其权限更新为管理员。")
            # else:
            #     print(f"用户 '{email}' 已存在且已经是管理员。")
            return

        # 创建新用户
        new_admin = User(
            email=email,
            is_admin=True,
            is_verified=False  # 手动创建的管理员默认不设置为已验证
        )
        new_admin.set_password(password) # 使用模型中的方法来设置密码

        db.add(new_admin)
        db.commit()
        db.refresh(new_admin)
        print(f"管理员用户 '{email}' 创建成功！")

    except Exception as e:
        db.rollback()
        print(f"创建管理员时发生错误: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='创建管理员用户')
    parser.add_argument('--email', type=str, required=True, help='管理员的邮箱地址')
    parser.add_argument('--password', type=str, required=True, help='管理员的密码 (至少6位)')

    args = parser.parse_args()

    if not User.is_valid_email(args.email):
        print("错误: 无效的邮箱格式。")
    elif len(args.password) < 6:
        print("错误: 密码长度至少需要6位。")
    else:
        create_admin_user(args.email, args.password) 