// 中危漏洞测试样本
// 预期扫描结果：中危、半自动修复、限期整改

// 1. 弱加密算法 MD5
const crypto = require('crypto');
function weak_md5(pwd){
    return crypto.createHash('md5').update(pwd).digest('hex');
}

// 2. 不安全随机数
function get_random_code(){
    return Math.random().toString().slice(2,8);
}

// 3. 宽泛CORS配置
const cors_option = {
    origin: "*"
}

// 4. 缺失安全响应头
function set_res_header(res){
    res.setHeader("Content-Type","text/json");
}