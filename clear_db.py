import sqlite3

def clear_database():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # 获取所有表名
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    table_names = [table[0] for table in tables]
    
    # 禁用外键约束
    cursor.execute("PRAGMA foreign_keys = OFF;")
    
    # 依次清空每个表
    for table_name in table_names:
        # 跳过sqlite_sequence表(用于自增主键)
        if table_name != 'sqlite_sequence':
            print(f"清空表: {table_name}")
            cursor.execute(f"DELETE FROM {table_name};")
    
    # 重置自增ID（如果sqlite_sequence表存在）
    if 'sqlite_sequence' in table_names:
        print("重置自增ID")
        cursor.execute("DELETE FROM sqlite_sequence;")
    else:
        print("数据库中没有sqlite_sequence表，跳过重置自增ID")
    
    # 重新启用外键约束
    cursor.execute("PRAGMA foreign_keys = ON;")
    
    # 提交更改
    conn.commit()
    
    # 压缩数据库
    cursor.execute("VACUUM;")
    
    # 关闭连接
    conn.close()
    
    print("数据库已清空")

if __name__ == "__main__":
    clear_database() 