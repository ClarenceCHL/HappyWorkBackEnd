import os
import logging
from dotenv import load_dotenv
from openai import OpenAI
from sqlalchemy.orm import sessionmaker
from models import engine, Chat, Message, Questionnaire, QuestionnaireResponse, User
import json
import uuid
import time
from datetime import datetime

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

# 创建数据库会话
Session = sessionmaker(bind=engine)

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

# 添加问卷提示词
QUESTIONNAIRE_PROMPT = """你是一位精通职场博弈、心理策略及人设经营的资深职场教练，尤其擅长应对职场PUA的情况。你的任务是根据用户的问卷答案，以精准的洞察力和丰富的职场智慧，提供一个高度定制化、可实操落地的《职场人设战略破局PUA》PDF报告。

你提供的报告必须包括以下几个部分：

1. 【心理痛点与PUA风险精准诊断】：
深度分析用户在职场中的心理状态、潜在被PUA风险点、痛点及根源原因，精准到位且具有启发性。

2. 【定制化职场人设战略方案】：
基于用户的期望人设，提出明确的人设经营策略，包括如何树立威望、表达自信、赢得尊重。

3. 【高阶职场话术与场景拆解】：
提供针对用户提到的具体职场情境的高效拆招话术、实操技巧与步骤指导，帮助用户快速有效应对职场冲突和PUA情境。

4. 【大佬级视角与职场智慧】：
从职场高人的视角，给出一套可快速提升职场竞争力、维护清晰职场边界的建议与方法，让用户迅速摆脱"职场炮灰"困境。

请确保你的输出：
- 语言接地气、通俗易懂、有逻辑，也要体现一些"高人智慧"，类似天涯经典职场神贴的风格；
- 观点明确、有针对性，内容结构清晰、有条理；
- 具有实操性，要具体到每一步每个阶段如何量化落地，用大白话说给用户听，便于用户在真实职场情境中应用
- 你要假设用户都是职场小白，所以讲的内容要非常详细，非常具体，非常落地，非常实操，非常通俗易懂，非常容易理解，非常容易执行。

报告最终以Markdown格式输出，便于后续转换为PDF格式。
请注意，报告里面不要出现任何带有*号和#号。"""

def get_chat_history(chat_id, max_messages=10):
    """从数据库获取聊天历史记录
    
    Args:
        chat_id: 聊天ID
        max_messages: 最大获取消息数量，默认10条
        
    Returns:
        消息列表，每条消息包含role和content
    """
    try:
        if not chat_id:
            logger.warning("未提供聊天ID，无法获取历史记录")
            return []
            
        session = Session()
        try:
            # 查询聊天记录
            messages = session.query(Message).filter(
                Message.chat_id == chat_id
            ).order_by(Message.created_at).all()
            
            # 格式化消息
            formatted_messages = []
            for msg in messages[-max_messages:]:  # 只获取最近的max_messages条消息
                formatted_messages.append({
                    "role": msg.role,
                    "content": msg.content
                })
                
            logger.info(f"获取到{len(formatted_messages)}条历史消息，聊天ID: {chat_id}")
            return formatted_messages
        except Exception as e:
            logger.error(f"获取聊天历史失败: {str(e)}")
            return []
        finally:
            session.close()
    except Exception as e:
        logger.error(f"获取聊天历史时发生异常: {str(e)}")
        return []

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
        # 修改为只在模式不存在或无效时才使用默认值
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
            
            # 无论之前用户选择什么，强制使用传入的模式，确保模式一致性
            print(f"后续对话使用模式: {mode}")
            
            # 获取历史对话记录作为上下文
            history = get_chat_history(chat_id)
            print(f"获取到{len(history)}条历史消息")
            
            # 明确检查mode是否为solution
            if mode == 'solution':
                # 解决方案模式，提供专业建议
                print("使用解决方案模式生成回复")
                advice = generate_solution_advice_with_context(message, history)
                print(f"生成解决方案回复: {advice[:100]}...")  # 只打印前100个字符
            else:
                # 默认模拟PUA对话模式
                print("使用模拟PUA对话模式生成回复")
                advice = generate_simulation_response_with_context(message, history)
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

def generate_simulation_response_with_context(message, history):
    """生成带上下文的模拟PUA对话回复"""
    try:
        # 构建带有历史上下文的消息列表
        messages = [{"role": "system", "content": SCENE_SIMULATION_PROMPT}]
        
        # 添加历史对话
        for msg in history:
            messages.append({"role": msg["role"], "content": msg["content"]})
        
        # 添加用户当前消息
        messages.append({"role": "user", "content": message})
        
        print(f"发送给模型的消息数: {len(messages)}")
        
        # 调用 DeepSeek API
        response = client.chat.completions.create(
            model="deepseek-chat",
            messages=messages,
            temperature=0.7,
            max_tokens=1000
        )
        
        return response.choices[0].message.content
    except Exception as e:
        logger.error(f"生成模拟回复失败: {str(e)}")
        return f"生成回复时发生错误：{str(e)}"

def generate_solution_advice_with_context(message, history):
    """生成带上下文的解决方案建议回复"""
    try:
        # 构建带有历史上下文的消息列表
        messages = [{"role": "system", "content": SOLUTION_PROMPT}]
        
        # 添加历史对话
        for msg in history:
            messages.append({"role": msg["role"], "content": msg["content"]})
        
        # 添加用户当前消息
        messages.append({"role": "user", "content": message})
        
        print(f"发送给模型的消息数: {len(messages)}")
        
        # 调用 DeepSeek API
        response = client.chat.completions.create(
            model="deepseek-chat",
            messages=messages,
            temperature=0.7,
            max_tokens=1000
        )
        
        return response.choices[0].message.content
    except Exception as e:
        logger.error(f"生成解决方案失败: {str(e)}")
        return f"生成解决方案时发生错误：{str(e)}"

def generate_simulation_response(message):
    """生成模拟PUA对话回复（不带上下文，保留用于兼容）"""
    try:
        logger.warning("使用不带上下文的函数生成回复，建议使用generate_simulation_response_with_context")
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
    """生成解决方案建议回复（不带上下文，保留用于兼容）"""
    try:
        logger.warning("使用不带上下文的函数生成回复，建议使用generate_solution_advice_with_context")
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

def generate_questionnaire_report(questionnaire_data):
    """
    根据用户提交的问卷数据生成专属报告
    
    Args:
        questionnaire_data: 包含问卷问题和回答的字典
        
    Returns:
        包含AI生成报告的字典
    """
    try:
        logger.info("开始生成问卷报告")
        
        # 构建用户提示词
        user_prompt = """以下是用户完成的一份关于"职场定制化人设破局战略"的详细问卷。用户希望根据这些回答得到一个专属于自己的、高价值的《职场人设战略破局PUA》报告。

请你结合每道问题与用户的回答，严格依据实际内容和用户真实需求，定制专属方案。

【问卷内容如下】：

"""
        
        # 添加问卷内容，格式化为易于AI理解的格式
        question_number = 1
        for question_id, answer in questionnaire_data.items():
            # 从allQuestions数组中找到对应的问题文本
            question_text = get_question_text_by_id(question_id)
            
            # 格式化答案
            formatted_answer = format_answer(answer)
            
            user_prompt += f"{question_number}. 问题: {question_text}\n"
            user_prompt += f"用户的回答: {formatted_answer}\n\n"
            question_number += 1
        
        user_prompt += "请严格结合以上内容输出报告。\n\n请你注意，报告里面不要出现任何带有*号和#号。"
        
        logger.info("提示词构建完成，准备调用DeepSeek API")
        
        # 调用DeepSeek API生成报告
        chat_completion = client.chat.completions.create(
            model="deepseek-chat",
            messages=[
                {"role": "system", "content": QUESTIONNAIRE_PROMPT},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.7,
            max_tokens=4000
        )
        
        # 提取生成的报告
        report = chat_completion.choices[0].message.content
        logger.info("成功生成问卷报告")
        
        # 生成唯一的预览链接ID
        preview_id = str(uuid.uuid4())
        preview_link = f"/preview/{preview_id}"
        
        # 更新用户的has_pdf字段
        session = Session()
        try:
            # 查询用户并更新其has_pdf字段
            user = session.query(User).filter(User.id == questionnaire_data.get('user_id')).first()
            if user:
                user.has_pdf = True
                session.commit()
                logger.info(f"已更新用户 {user.id} 的has_pdf字段为True")
        except Exception as e:
            session.rollback()
            logger.error(f"更新用户has_pdf字段失败: {str(e)}")
        finally:
            session.close()
        
        return {
            "status": "success",
            "report": report,
            "preview_link": preview_link
        }
    except Exception as e:
        logger.error(f"生成问卷报告时出错: {str(e)}")
        return {
            "status": "error",
            "message": f"生成报告失败: {str(e)}"
        }

def get_question_text_by_id(question_id):
    """
    根据问题ID获取问题文本
    这个函数需要与前端的问题ID保持一致
    """
    # 问题ID到文本的映射，与前端QuestionnairePage.tsx中的ID保持一致
    questions_map = {
        's1q1': '当你感觉到被上司批评或针对时，你最常见的反应是什么？',
        's1q2': '面对职场上的无理要求（如无理由加班），你通常如何应对？',
        's1q3': '当你发现自己的功劳被他人占据或弱化时，你的第一反应是？',
        's1q4': '你目前在职场中经常遇到哪些困扰？（最多选3项）',
        's1q5': '下列哪些情景会使你内心感到焦虑或不安？（最多选3项）',
        's1q6': '你认为自己目前最缺乏的职场能力有哪些？（最多选3项）',
        's1q7': '请简单描述最近一次让你深感不舒服的职场经历。',
        's1q8': '你觉得职场PUA对你最大的影响是什么？',
        's2q1': '你希望在职场中的人设是怎样的？',
        's2q2': '当前你的职场状态，更接近哪一种？',
        's2q3': '你想通过定制化人设战略解决哪些问题？（最多选3项）',
        's2q4': '下列哪些品质你认为是理想人设必须具备的？（最多选3项）',
        's2q5': '描述一下你理想中最完美的职场状态或人设。',
        's2q6': '你认为哪些因素阻碍了你达到理想的职场人设？',
        's3q1': '面对职场"画大饼"而不兑现的情况，你通常的反应是？',
        's3q2': '在下面哪些情境下，你特别希望能获得高人的指导或智慧？（最多选3项）',
        's3q3': '你最希望掌握哪种具体的职场沟通技巧或话术？',
        's3q4': '请简述一次你觉得自己成功应对职场冲突的经历。',
        's3q5': '如果遇到职场中难以拒绝的要求，你通常怎么说？请举一个具体的例子。',
        's3q6': '如果现在职场有一位高人给你指导，你最想得到哪方面的建议或点拨？'
    }
    
    return questions_map.get(question_id, f"问题ID: {question_id}")

def format_answer(answer):
    """
    格式化答案，将选项值转换为可读文本
    """
    if isinstance(answer, list):
        # 处理多选题
        return ", ".join(answer)
    else:
        # 处理单选题或简答题
        return str(answer)

def save_questionnaire(user_id, answers_data):
    """
    保存问卷数据到数据库
    
    Args:
        user_id: 用户ID
        answers_data: 问卷答案数据
        
    Returns:
        包含问卷ID的字典
    """
    try:
        session = Session()
        try:
            # 创建新的问卷记录
            questionnaire = Questionnaire(
                user_id=user_id,
                answers=json.dumps(answers_data, ensure_ascii=False),
                has_report=False
            )
            session.add(questionnaire)
            session.commit()
            
            logger.info(f"问卷数据保存成功，ID: {questionnaire.id}")
            return {
                "status": "success",
                "questionnaire_id": questionnaire.id
            }
        except Exception as e:
            session.rollback()
            logger.error(f"保存问卷数据失败: {str(e)}")
            return {
                "status": "error",
                "message": f"保存问卷数据失败: {str(e)}"
            }
        finally:
            session.close()
    except Exception as e:
        logger.error(f"保存问卷数据时发生异常: {str(e)}")
        return {
            "status": "error",
            "message": f"服务器错误: {str(e)}"
        }

def save_questionnaire_response(questionnaire_id, response_data, preview_link):
    """
    保存问卷报告到数据库
    
    Args:
        questionnaire_id: 问卷ID
        response_data: AI生成的报告内容
        preview_link: 预览链接
        
    Returns:
        包含状态信息的字典
    """
    try:
        print(f"开始保存问卷报告，问卷ID: {questionnaire_id}")
        print(f"预览链接: {preview_link}")
        print(f"报告内容长度: {len(response_data) if response_data else 0}")
        print(f"报告内容示例: {response_data[:100]}..." if response_data and len(response_data) > 100 else response_data)
        
        session = Session()
        try:
            # 创建新的问卷报告记录
            response = QuestionnaireResponse(
                questionnaire_id=questionnaire_id,
                response_content=response_data,
                preview_link=preview_link
            )
            session.add(response)
            
            # 更新问卷状态为已生成报告
            questionnaire = session.query(Questionnaire).filter(
                Questionnaire.id == questionnaire_id
            ).first()
            
            if questionnaire:
                questionnaire.has_report = True
                print(f"更新问卷状态为已生成报告，问卷ID: {questionnaire_id}")
            else:
                print(f"警告：未找到对应的问卷，ID: {questionnaire_id}")
            
            session.commit()
            
            logger.info(f"问卷报告保存成功，问卷ID: {questionnaire_id}")
            print(f"问卷报告保存成功，报告ID: {response.id}")
            
            # 查询并打印报告信息，以确认保存成功
            saved_response = session.query(QuestionnaireResponse).filter(
                QuestionnaireResponse.id == response.id
            ).first()
            
            if saved_response:
                print(f"确认报告已保存，ID: {saved_response.id}")
                print(f"保存的预览链接: {saved_response.preview_link}")
                print(f"保存的报告内容长度: {len(saved_response.response_content) if saved_response.response_content else 0}")
            else:
                print(f"警告：无法确认报告是否成功保存")
            
            return {
                "status": "success",
                "response_id": response.id
            }
        except Exception as e:
            session.rollback()
            logger.error(f"保存问卷报告失败: {str(e)}")
            print(f"保存问卷报告失败: {str(e)}")
            import traceback
            traceback.print_exc()
            return {
                "status": "error",
                "message": f"保存问卷报告失败: {str(e)}"
            }
        finally:
            session.close()
    except Exception as e:
        logger.error(f"保存问卷报告时发生异常: {str(e)}")
        print(f"保存问卷报告时发生异常: {str(e)}")
        import traceback
        traceback.print_exc()
        return {
            "status": "error",
            "message": f"服务器错误: {str(e)}"
        } 