package burp.result;

import lombok.Data;

/**
 * 不安全HTTP方法测试结果类
 */
@Data
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

    public UnsafeMethodTestResult(int id, String url, String originalMethod, String modifiedMethod,
                                  int statusCode, boolean vulnerable, boolean needsConfirmation,
                                  String requestHeaders, String requestBody,
                                  String responseHeaders, String responseBody) {
        this.id = id;
        this.url = url;
        this.originalMethod = originalMethod;
        this.modifiedMethod = modifiedMethod;
        this.statusCode = statusCode;
        this.vulnerable = vulnerable;
        this.needsConfirmation = needsConfirmation;
        this.selected = false;
        this.requestHeaders = requestHeaders;
        this.requestBody = requestBody;
        this.responseHeaders = responseHeaders;
        this.responseBody = responseBody;
    }
}