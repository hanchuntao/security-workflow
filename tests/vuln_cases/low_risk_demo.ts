// 低危漏洞测试样本
// 预期扫描结果：低危、全自动静默修复、自动闭环

// 废弃调试代码
console.log("debug test info");
console.log("temp log");

// 无效安全注释
// 临时测试密钥：123456

// 未使用高危导入
import * as unsafeCrypto from 'crypto'
