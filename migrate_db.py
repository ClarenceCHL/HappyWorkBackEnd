import sqlite3

def migrate_database():
    # 连接到数据库
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    try:
        # 创建临时表
        cursor.execute('''
            CREATE TABLE messages_temp (
                id INTEGER PRIMARY KEY,
                chat_id INTEGER,
                role VARCHAR(20),
                content TEXT,
                images TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (chat_id) REFERENCES chats (id)
            )
        ''')
        
        # 复制数据到临时表，将 conversation_id 映射到 chat_id
        cursor.execute('''
            INSERT INTO messages_temp (id, chat_id, role, content, created_at)
            SELECT id, conversation_id, role, content, created_at FROM messages
        ''')
        
        # 删除旧表
        cursor.execute('DROP TABLE messages')
        
        # 重命名临时表
        cursor.execute('ALTER TABLE messages_temp RENAME TO messages')
        
        print("数据库迁移成功完成！")
            
    except Exception as e:
        print(f"迁移过程中发生错误: {str(e)}")
        conn.rollback()
    finally:
        conn.commit()
        conn.close()

if __name__ == "__main__":
    migrate_database() 