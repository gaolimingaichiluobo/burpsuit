package burp.result;

import burp.session.TestSession;
import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * 越权测试结果类
 */
@Data
@AllArgsConstructor
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
    private String resultReson;

}