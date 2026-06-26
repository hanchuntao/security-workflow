// Medium-risk vulnerability test sample
// Expected scan result: Medium, semi-auto fix, deadline-tracked remediation

// 1. Weak encryption algorithm MD5
const crypto = require('crypto');
function weak_md5(pwd){
    return crypto.createHash('md5').update(pwd).digest('hex');
}

// 2. Insecure random number
function get_random_code(){
    return Math.random().toString().slice(2,8);
}

// 3. Overly permissive CORS configuration
const cors_option = {
    origin: "*"
}

// 4. Missing security response headers
function set_res_header(res){
    res.setHeader("Content-Type","text/json");
}
