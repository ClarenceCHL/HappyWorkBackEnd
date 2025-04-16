import os
import logging
from dotenv import load_dotenv
from openai import OpenAI

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

DEEPSEEK_API_KEY = os.getenv('DEEPSEEK_API_KEY')

if not DEEPSEEK_API_KEY:
    logger.error("DEEPSEEK_API_KEY 未设置！请在 .env 文件中设置 DEEPSEEK_API_KEY")
    raise ValueError("DEEPSEEK_API_KEY 未设置")

# 初始化 OpenAI 客户端
client = OpenAI(
    api_key=DEEPSEEK_API_KEY,
    base_url="https://api.deepseek.com/v1"
)

# 系统角色设定
SCENE_SIMULATION_PROMPT = """你是一位经验丰富的职场PUA角色扮演专家，擅长扮演职场中有心理操控（PUA）行为的职场人士。你的角色设定应该：
1. 避免透露身份：请不要提及任何技术细节或涉及AI的相关信息，用户无需知道你是由系统生成的人工智能，你的角色是一个职场PUA大师。
2. 专注职场PUA：你只能处理与职场PUA行为相关的场景表演，任何与此无关的内容请拒绝回答，并用PUA的口吻提醒用户重新告知你与职场PUA相关的场景。
3. 表演的专业性：你的语言应该非常带有PUA的口吻，精神控制，服从性测试，打压洗脑，等等，能够深刻理解且复现用户遭遇的具体场景，针对具体场景提供高度还原的PUA对话，要把自己代入到是用户描述中的施害者，用词用语语气高度还原，让用户感受到真实性。
4. 简洁、有条理：你的对话应该高度拟人化，用户提供的场景还原化，与真实对话方式一样。
5. 每轮对话要保持多样性，不要出现重复的对话内容"""

SOLUTION_PROMPT = """你是一位经验丰富的职场反PUA的心理咨询专家，擅长处理和应对职场中的PUA行为以及职场人的心理问题。你的角色设定应该：
1. 针对用户实际遭遇，提供具体且易于理解的应对话术和行动建议。
2. 用通俗、贴心的话语进行安慰，站在用户的角度上去理解用户的感受，鼓励用户多描述自己的感受，让用户觉得你真正在用心倾听。
3. 你只能处理与职场PUA行为相关的心理咨询，任何与此无关的内容请拒绝回答，并用贴心的口吻提醒用户重新告知你与职场PUA相关的场景。
4. 简洁、有条理，你的对话应该高度拟人化，用户提供的场景还原化，与真实对话方式一样。
5. 每轮对话要保持多样性，不要出现重复的对话内容
6. 请不要提及任何技术细节或涉及AI的相关信息，用户无需知道你是由系统生成的人工智能，你的角色是一个职场反PUA心理咨询专家。"""

def build_prompt(data):
    """构建完整的提示词，生成针对性的、具有共情和专业性的应对方案"""
    try:
        print(f"构建提示词，接收数据: {data}")
        print(f"数据模式: {data.get('mode')}")
        
        # 检查模式是否有效，避免使用无效默认值
        mode = data.get('mode')
        if mode not in ['simulation', 'solution']:
            # 只有在模式无效或不存在时才使用默认值
            mode = 'simulation'
            print(f"提示词使用默认模式: {mode}")
        else:
            print(f"提示词使用用户选择的模式: {mode}")
        
        # 检查是否是后续对话
        if 'message' in data and 'type' in data and data['type'] == 'follow_up':
            # 构建后续对话的提示词
            if mode == 'simulation':
                return f"""{SCENE_SIMULATION_PROMPT}
            
用户说：{data['message']}

请以高度场景还原、深度代入PUA施害者立场的方式回应用户，提供原场景PUA复现。记住要：
1. 语言带有PUA的口吻，精神控制，服从性测试，打压洗脑，等等
2. 能够深刻理解且复现用户遭遇的具体场景
3. 针对用户提供的具体场景提供高度还原的PUA对话
4. 用词用语语气高度还原，让用户感受到真实性
5. 每轮对话要保持多样性，不要出现重复的对话内容"""
            else:
                return f"""{SOLUTION_PROMPT}

用户说：{data['message']}

请以心理咨询专家的角度，深度共情，并给出建设性建议，记住要：
1. 提供具体且易于理解的应对话术和行动建议。
2. 用通俗、贴心的话语进行安慰，站在受害者的角度去理解感受，鼓励用户多描述自己的感受，让用户觉得你真正在用心倾听。
3. 只能处理与职场PUA行为相关的心理咨询，任何与此无关的内容请拒绝回答，并用贴心的口吻提醒用户重新告知与职场PUA相关的场景。
4. 简洁、有条理，对话应该高度拟人化，用户提供的场景还原化，与真实对话方式一样。
5. 每轮对话要保持多样性，不要出现重复的对话内容
6. 请不要提及任何技术细节或涉及AI的相关信息，用户无需知道你是由系统生成的人工智能，你的角色是一个职场反PUA心理咨询专家。"""
        else:
            # 将数组转换为字符串
            pua_types = '、'.join(data.get('puaType', [])) if isinstance(data.get('puaType'), list) else str(data.get('puaType', ''))
            perpetrators = '、'.join(data.get('perpetrator', [])) if isinstance(data.get('perpetrator'), list) else str(data.get('perpetrator', ''))
            severity = str(data.get('severity', ''))
            description = str(data.get('description', ''))
            
            if data.get('mode') == 'simulation':
                return f"""{SCENE_SIMULATION_PROMPT}

用户的情况如下：
- PUA类型：{pua_types}
- 严重程度：{severity}
- 施害者身份：{perpetrators}
- 详细描述：{description}

请以高度场景还原、深度代入PUA施害者立场的方式回应用户，提供原场景PUA复现。记住要：
1. 语言带有PUA的口吻，精神控制，服从性测试，打压洗脑，等等
2. 能够深刻理解且复现用户遭遇的具体场景
3. 针对用户提供的具体场景提供高度还原的PUA对话
4. 用词用语语气高度还原，让用户感受到真实性
5. 每轮对话要保持多样性，不要出现重复的对话内容"""
            else:
                return f"""{SOLUTION_PROMPT}

用户遇到的情况：
- PUA类型：{pua_types}
- 严重程度：{severity}
- 施害者身份：{perpetrators}
- 详细描述：{description}

请以心理咨询专家的角度，深度共情，并给出建设性建议，记住要：
1. 提供具体且易于理解的应对话术和行动建议。
2. 用通俗、贴心的话语进行安慰，站在受害者的角度去理解感受，鼓励用户多描述自己的感受，让用户觉得你真正在用心倾听。
3. 只能处理与职场PUA行为相关的心理咨询，任何与此无关的内容请拒绝回答，并用贴心的口吻提醒用户重新告知与职场PUA相关的场景。
4. 简洁、有条理，对话应该高度拟人化，用户提供的场景还原化，与真实对话方式一样。
5. 每轮对话要保持多样性，不要出现重复的对话内容
6. 请不要提及任何技术细节或涉及AI的相关信息，用户无需知道你是由系统生成的人工智能，你的角色是一个职场反PUA心理咨询专家。"""
    except Exception as e:
        logger.error(f"构建提示词时出错: {str(e)}")
        raise

def generate_pua_response(chat_data):
    """根据用户输入生成PUA回复"""
    try:
        print("========== 调用generate_pua_response ==========")
        print("生成PUA回复，输入数据:", chat_data)  # 添加日志
        print(f"模式: {chat_data.get('mode')}")  # 明确打印模式值
        
        # 获取对话模式，确保使用用户传入的模式
        # 之前设置了默认值为'simulation'，这可能导致用户选择的'solution'被覆盖
        # 修改为只在模式不存在时才使用默认值
        mode = chat_data.get('mode')
        if mode not in ['simulation', 'solution']:
            # 只有在模式无效或不存在时才使用默认值
            mode = 'simulation'
            print(f"使用默认模式: {mode}")
        else:
            print(f"使用用户选择的模式: {mode}")
        
        # 检查对话类型
        if chat_data.get('type') == 'follow_up':
            # 处理后续对话
            message = chat_data.get('message', '')
            chat_id = chat_data.get('chatId')
            
            # 明确检查mode是否为solution
            if mode == 'solution':
                # 解决方案模式，提供专业建议
                print("使用解决方案模式生成回复")
                advice = generate_solution_advice(message)
                print(f"生成解决方案回复: {advice[:100]}...")  # 只打印前100个字符
            else:
                # 默认模拟PUA对话模式
                print("使用模拟PUA对话模式生成回复")
                advice = generate_simulation_response(message)
                print(f"生成模拟PUA回复: {advice[:100]}...")  # 只打印前100个字符
                
            return {
                "status": "success",
                "advice": advice,
                "mode": mode  # 返回使用的模式，便于前端识别
            }
            
        else:
            # 处理新建咨询
            pua_type = chat_data.get('puaType', [])
            severity = chat_data.get('severity', '')
            perpetrator = chat_data.get('perpetrator', [])
            description = chat_data.get('description', '')
            
            # 检查是否为solution模式
            if mode == 'solution':
                print("使用解决方案模式生成初始回复")
                advice = generate_initial_solution(pua_type, severity, perpetrator, description)
                print(f"生成解决方案初始回复: {advice[:100]}...")  # 只打印前100个字符
            else:
                # 默认采用模拟PUA对话模式
                print("使用模拟PUA对话模式生成初始回复")
                advice = generate_initial_response(pua_type, severity, perpetrator, description)
                print(f"生成模拟PUA初始回复: {advice[:100]}...")  # 只打印前100个字符
            
            return {
                "status": "success",
                "advice": advice,
                "mode": mode  # 返回实际使用的模式
            }
            
    except Exception as e:
        print(f"生成回复失败: {str(e)}")
        import traceback
        traceback.print_exc()  # 打印完整错误栈
        return {"status": "error", "message": str(e), "mode": chat_data.get('mode', 'simulation')}

def save_conversation(user_id, data, response):
    """保存对话记录（待实现）"""
    # TODO: 实现对话记录的保存功能
    pass 

def generate_simulation_response(message):
    """生成模拟PUA对话回复"""
    try:
        # 构建提示词
        prompt = f"""{SCENE_SIMULATION_PROMPT}
        
用户说：{message}

请以高度场景还原、深度代入PUA施害者立场的方式回应用户，提供原场景PUA复现。"""

        # 调用 DeepSeek API
        response = client.chat.completions.create(
            model="deepseek-chat",
            messages=[
                {"role": "system", "content": SCENE_SIMULATION_PROMPT},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=1000
        )
        
        return response.choices[0].message.content
    except Exception as e:
        logger.error(f"生成模拟回复失败: {str(e)}")
        return f"生成回复时发生错误：{str(e)}"

def generate_solution_advice(message):
    """生成解决方案建议回复"""
    try:
        # 构建提示词
        prompt = f"""{SOLUTION_PROMPT}

用户说：{message}

请直接以对话形式回复用户，不要输出任何表示语气、停顿或其他指导的括号内容，例如'(停顿一下)'、'(用温和的语气)'等。这些都应该融入到您的回复语气和措辞中，而不是单独输出。"""

        # 调用 DeepSeek API
        response = client.chat.completions.create(
            model="deepseek-chat",
            messages=[
                {"role": "system", "content": SOLUTION_PROMPT},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=1000
        )
        
        return response.choices[0].message.content
    except Exception as e:
        logger.error(f"生成解决方案失败: {str(e)}")
        return f"生成解决方案时发生错误：{str(e)}"

def generate_initial_response(pua_type, severity, perpetrator, description):
    """生成初始对话回复"""
    try:
        # 将数组转换为字符串
        pua_types = '、'.join(pua_type) if isinstance(pua_type, list) else str(pua_type)
        perpetrators = '、'.join(perpetrator) if isinstance(perpetrator, list) else str(perpetrator)
        
        # 构建提示词
        prompt = f"""{SCENE_SIMULATION_PROMPT}

用户的情况如下：
- PUA类型：{pua_types}
- 严重程度：{severity}
- 施害者身份：{perpetrators}
- 详细描述：{description}

请以高度场景还原、深度代入PUA施害者立场的方式回应用户，提供原场景PUA复现。"""

        # 调用 DeepSeek API
        response = client.chat.completions.create(
            model="deepseek-chat",
            messages=[
                {"role": "system", "content": SCENE_SIMULATION_PROMPT},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=1000
        )
        
        return response.choices[0].message.content
    except Exception as e:
        logger.error(f"生成初始回复失败: {str(e)}")
        return f"生成初始回复时发生错误：{str(e)}"

def generate_initial_solution(pua_type, severity, perpetrator, description):
    """生成初始对话的解决方案"""
    try:
        # 将数组转换为字符串
        pua_types = '、'.join(pua_type) if isinstance(pua_type, list) else str(pua_type)
        perpetrators = '、'.join(perpetrator) if isinstance(perpetrator, list) else str(perpetrator)
        
        # 构建提示词
        prompt = f"""{SOLUTION_PROMPT}

用户遇到的情况：
- PUA类型：{pua_types}
- 严重程度：{severity}
- 施害者身份：{perpetrators}
- 详细描述：{description}

作为职场反PUA心理咨询专家，请用温暖贴心的语言深度共情用户的处境，提供具体的应对话术和行动指南，严格围绕职场PUA场景进行心理疏导，对无关话题会温柔提醒，并通过自然生动的对话方式，让用户感受到真实的情感共鸣和实用支持。
请直接以对话形式回复用户，不要输出任何表示语气、停顿或其他指导的括号内容，例如'(停顿一下)'、'(用温和的语气)'等。这些都应该融入到您的回复语气和措辞中，而不是单独输出。"""

        # 调用 DeepSeek API
        response = client.chat.completions.create(
            model="deepseek-chat",
            messages=[
                {"role": "system", "content": SOLUTION_PROMPT},  # 使用解决方案提示词
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=1000
        )
        
        return response.choices[0].message.content
    except Exception as e:
        logger.error(f"生成初始解决方案失败: {str(e)}")
        return f"生成初始解决方案时发生错误：{str(e)}" 