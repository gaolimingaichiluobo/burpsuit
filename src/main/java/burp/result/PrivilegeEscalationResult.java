package burp.result;

import burp.session.TestSession;
import lombok.Data;

/**
 * 越权测试结果类
 */
@Data
public class PrivilegeEscalationResult {
    private int id;
    private String url;
    private String testType; // 水平越权 or 垂直越权
    private String paramName; // 修改的参数名
    private String originalValue; // 原始值
    private String modifiedValue; // 修改后的值
    private int originalStatusCode; // 原始状态码
    private int modifiedStatusCode; // 修改后状态码
    private boolean vulnerable; // 是否存在漏洞
    private boolean needsConfirmation; // 是否需要确认
    private boolean selected; // 是否被选中
    private String originalRequestHeaders;
    private String originalRequestBody;
    private String originalResponseHeaders;
    private String originalResponseBody;
    private String modifiedRequestHeaders;
    private String modifiedRequestBody;
    private String modifiedResponseHeaders;
    private String modifiedResponseBody;
    private TestSession originalSession; // 原始会话
    private TestSession modifiedSession; // 修改后会话

    public PrivilegeEscalationResult(int id, String url, String testType, String paramName,
                                     String originalValue, String modifiedValue,
                                     int originalStatusCode, int modifiedStatusCode,
                                     boolean vulnerable, boolean needsConfirmation,
                                     String originalRequestHeaders, String originalRequestBody,
                                     String originalResponseHeaders, String originalResponseBody,
                                     String modifiedRequestHeaders, String modifiedRequestBody,
                                     String modifiedResponseHeaders, String modifiedResponseBody,
                                     TestSession originalSession, TestSession modifiedSession) {
        this.id = id;
        this.url = url;
        this.testType = testType;
        this.paramName = paramName;
        this.originalValue = originalValue;
        this.modifiedValue = modifiedValue;
        this.originalStatusCode = originalStatusCode;
        this.modifiedStatusCode = modifiedStatusCode;
        this.vulnerable = vulnerable;
        this.needsConfirmation = needsConfirmation;
        this.selected = false;
        this.originalRequestHeaders = originalRequestHeaders;
        this.originalRequestBody = originalRequestBody;
        this.originalResponseHeaders = originalResponseHeaders;
        this.originalResponseBody = originalResponseBody;
        this.modifiedRequestHeaders = modifiedRequestHeaders;
        this.modifiedRequestBody = modifiedRequestBody;
        this.modifiedResponseHeaders = modifiedResponseHeaders;
        this.modifiedResponseBody = modifiedResponseBody;
        this.originalSession = originalSession;
        this.modifiedSession = modifiedSession;
    }
}