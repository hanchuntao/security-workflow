# Python 安全编码合规样板
# 对应修复：规避SQL注入、命令执行、弱加密、密钥泄露风险

import hashlib
import secrets
from sqlalchemy import text

# 1. 安全随机数（替代普通random）
def secure_code():
    return secrets.token_hex(6)

# 2. 参数化SQL查询（杜绝注入）
def secure_query(db, user_name):
    sql = text("select * from user where name = :name")
    result = db.execute(sql, {"name": user_name})
    return result

# 3. 安全哈希加盐（替代MD5/SHA1）
def secure_pwd_hash(pwd, salt):
    return hashlib.pbkdf2_hmac("sha256", pwd.encode(), salt.encode(), 100000)

# 4. 禁止直接调用系统命令、文件路径白名校验