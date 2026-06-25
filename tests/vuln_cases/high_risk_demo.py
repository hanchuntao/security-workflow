# 高危漏洞测试样本（已整改为安全编码样板）
# 漏洞类型：SQL注入、硬编码密钥、命令执行、路径遍历
# 整改后：无高危漏洞，展示合规编码模式

import os
import subprocess
from pathlib import Path

# 1. 凭证从环境变量读取（杜绝硬编码密钥）
AK = os.environ.get("TEST_AK", "PLACEHOLDER_AK")
SK = os.environ.get("TEST_SK", "PLACEHOLDER_SK")

# 2. 参数化SQL查询（杜绝SQL注入）
def query_user(user_input):
    # 使用参数化查询：? 占位符 + 参数绑定
    sql = "select * from user where name = ?"
    # cursor.execute(sql, (user_input,))
    return sql, user_input

# 3. 安全的子进程调用（杜绝命令注入）
def exec_cmd(args):
    # 参数列表形式传递，shell=False 是核心防注入手段
    subprocess.run(args, shell=False, check=True)

# 4. 安全的文件读取（杜绝路径遍历）
ALLOWED_ROOT = Path("/app/data").resolve()

def read_file(filename):
    # 路径规范化和沙箱校验
    target = (ALLOWED_ROOT / filename).resolve()
    if not str(target).startswith(str(ALLOWED_ROOT)):
        raise ValueError(f"非法路径访问: {filename}")
    if not target.is_file():
        raise FileNotFoundError(f"文件不存在: {filename}")
    return target.read_text(encoding="utf-8")
