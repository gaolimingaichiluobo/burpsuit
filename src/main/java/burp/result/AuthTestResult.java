package burp.result;

import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * 未授权测试结果类
 */
@Data
@AllArgsConstructor
public class AuthTestResult {
    private int id;
    private String url;
    private int statusCode;
    private boolean vulnerable;
    private boolean needsConfirmation;
    private boolean selected;
    private String requestHeaders;
    private String requestBody;
    private String responseHeaders;
    private String responseBody;
    private String resultReson;
}