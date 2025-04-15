import sys
import os
from dotenv import load_dotenv

# 确保当前目录在路径中
project_path = os.path.dirname(os.path.abspath(__file__))
if project_path not in sys.path:
    sys.path.insert(0, project_path)

# 加载环境变量
load_dotenv(os.path.join(project_path, '.env'))

# 导入WSGI应用
from wsgi_app import application

# PythonAnywhere需要此变量
application = application 