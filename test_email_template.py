import os

def test_email_template():
    # 从模板文件读取HTML内容
    template_path = os.path.join(os.path.dirname(__file__), 'templates', 'email_verification.html')
    try:
        with open(template_path, 'r', encoding='utf-8') as file:
            template = file.read()
        
        # 替换模板中的验证码
        html_content = template.format(code="123456")
        
        print("模板读取成功！")
        print(f"模板路径: {template_path}")
        print(f"替换验证码后的内容片段: {html_content[:100]}...")
        return True
    except Exception as e:
        print(f"测试失败: {str(e)}")
        return False

if __name__ == "__main__":
    test_email_template() 