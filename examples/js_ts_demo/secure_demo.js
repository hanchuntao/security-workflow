// JS/TS secure coding compliance template
const crypto = require('crypto');

// 1. Secure random number generation
function secure_random(){
    return crypto.randomBytes(6).toString('hex');
}

// 2. Compliant CORS configuration (restricted domain)
const secure_cors = {
    origin: "https://company-domain.com",
    credentials: true
}

// 3. Complete security response headers
function set_secure_header(res){
    res.setHeader("X-Frame-Options","DENY");
    res.setHeader("X-XSS-Protection","1; mode=block");
    res.setHeader("Strict-Transport-Security","max-age=31536000;includeSubDomains");
}
