// JS/TS 安全编码合规样板
const crypto = require('crypto');

// 1. 安全随机数
function secure_random(){
    return crypto.randomBytes(6).toString('hex');
}

// 2. 合规CORS配置（限制域名）
const secure_cors = {
    origin: "https://company-domain.com",
    credentials: true
}

// 3. 完整安全响应头
function set_secure_header(res){
    res.setHeader("X-Frame-Options","DENY");
    res.setHeader("X-XSS-Protection","1; mode=block");
    res.setHeader("Strict-Transport-Security","max-age=31536000;includeSubDomains");
}
