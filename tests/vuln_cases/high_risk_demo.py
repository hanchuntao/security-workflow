# High-risk vulnerability test sample (for plugin scan validation)
# Vulnerability types: SQL injection, hardcoded keys, command execution, path traversal
# Expected scan result: High, forbid auto-fix, block deployment, requires manual remediation

# 1. Hardcoded credentials (High)
AK = "fake-access-key-for-test-only"
SK = "fake-secret-key-for-test-only"

# 2. Raw SQL concatenation (SQL injection — High)
def query_user(user_input):
    sql = "select * from user where name = '" + user_input + "'"
    return sql

# 3. System command execution (command injection — High)
import os
def exec_cmd(cmd):
    os.system(cmd)

# 4. Arbitrary file read (path traversal — High)
def read_file(filename):
    f = open(filename, "r")
    return f.read()
