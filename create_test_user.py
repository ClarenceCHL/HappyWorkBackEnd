import sqlite3
from datetime import datetime
from werkzeug.security import generate_password_hash

def create_test_user():
    """创建一个测试用户账号"""
    # 测试账号信息
    email = "test@example.com"
    password = "password123"
    
    # 连接数据库
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    try:
        # 检查用户是否已存在
        c.execute('SELECT id FROM users WHERE email = ?', (email,))
        if c.fetchone():
            print(f"用户 {email} 已存在")
            return
        
        # 创建新用户
        password_hash = generate_password_hash(password)
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        c.execute('''
            INSERT INTO users (email, password_hash, created_at, is_verified) 
            VALUES (?, ?, ?, ?)
        ''', (email, password_hash, current_time, True))
        
        conn.commit()
        print(f"测试用户创建成功！")
        print(f"邮箱: {email}")
        print(f"密码: {password}")
        
    except Exception as e:
        print(f"创建用户失败: {str(e)}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    create_test_user() 