// Java 安全编码合规样板
import java.security.SecureRandom;

public class SecureDemo {
    // 安全随机数
    public static String secureCode(){
        SecureRandom random = new SecureRandom();
        return String.valueOf(random.nextInt(999999));
    }

    // 安全参数化查询、脱敏工具、安全配置参考样板
}
