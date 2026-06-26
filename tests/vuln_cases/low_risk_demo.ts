// Low-risk vulnerability test sample
// Expected scan result: Low, full-auto silent fix, auto-closed

// Deprecated debug code
console.log("debug test info");
console.log("temp log");

// Invalid security comment
// 临时测试密钥：123456

// Unused high-risk import
import * as unsafeCrypto from 'crypto'
