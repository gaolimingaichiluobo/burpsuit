package burp.session;

import lombok.Data;

/**
 * 越权测试会话类
 * 用于存储不同权限级别的用户会话信息
 */
@Data
public class TestSession {
    private String name;
    private String cookies;
    private String authorization;
    private int privilegeLevel; // 权限级别，数字越大权限越高

    public TestSession(String name, String cookies, String authorization, int privilegeLevel) {
        this.name = name;
        this.cookies = cookies;
        this.authorization = authorization;
        this.privilegeLevel = privilegeLevel;
    }
}