package burp.result;

import lombok.Data;

/**
 * CSRF测试结果类
 */
@Data
public class CsrfTestResult {
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
    private String modifiedReferer;
    public CsrfTestResult(int id, String url, int statusCode, boolean vulnerable, boolean needsConfirmation,
                          String requestHeaders, String requestBody, String responseHeaders, String responseBody,
                          String modifiedReferer) {
        this.id = id;
        this.url = url;
        this.statusCode = statusCode;
        this.vulnerable = vulnerable;
        this.needsConfirmation = needsConfirmation;
        this.selected = false;
        this.requestHeaders = requestHeaders;
        this.requestBody = requestBody;
        this.responseHeaders = responseHeaders;
        this.responseBody = responseBody;
        this.modifiedReferer = modifiedReferer;
    }
}