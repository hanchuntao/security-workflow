# Python secure coding compliance template
# Covers: SQL injection prevention, command execution, weak crypto, key leak risks

import hashlib
import secrets
from sqlalchemy import text

# 1. Secure random (replaces unsafe random module)
def secure_code():
    return secrets.token_hex(6)

# 2. Parameterized SQL query (injection-proof)
def secure_query(db, user_name):
    sql = text("select * from user where name = :name")
    result = db.execute(sql, {"name": user_name})
    return result

# 3. Secure salted hashing (replaces MD5/SHA1)
def secure_pwd_hash(pwd, salt):
    return hashlib.pbkdf2_hmac("sha256", pwd.encode(), salt.encode(), 100000)

# 4. Never call system commands directly; use whitelist path validation for file I/O
