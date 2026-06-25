# 高危漏洞测试样本（用于插件扫描校验）
# 漏洞类型：SQL注入、硬编码密钥、命令执行、路径遍历
# 预期扫描结果：高危、禁止自动修复、阻断上线、待人工整改

# 1. 硬编码密钥（高危）
AK = "fake-access-key-for-test-only"
SK = "fake-secret-key-for-test-only"

# 2. 原生SQL拼接（SQL注入高危）
def query_user(user_input):
    sql = "select * from user where name = '" + user_input + "'"
    return sql

# 3. 系统命令执行（命令注入高危）
import os
def exec_cmd(cmd):
    os.system(cmd)

# 4. 任意文件读取（路径遍历高危）
def read_file(filename):
    f = open(filename, "r")
    return f.read()
