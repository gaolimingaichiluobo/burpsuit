package burp.result;

import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * 不安全HTTP方法测试结果类
 */
@Data
@AllArgsConstructor
public class UnsafeMethodTestResult {
    private int id;
    private String url;
    private String originalMethod;
    private String modifiedMethod;
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