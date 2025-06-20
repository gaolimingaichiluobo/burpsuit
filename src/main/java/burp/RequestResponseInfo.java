package burp;

import lombok.Data;

@Data
public class RequestResponseInfo {
    private int id;
    private String url;
    private String method;
    private int statusCode;
    private String requestHeaders;
    private String requestBody;
    private String responseBody;
    private boolean selected;
    private IHttpRequestResponse messageInfo;
    private IExtensionHelpers helpers;

    public RequestResponseInfo(IExtensionHelpers helpers,
                               IHttpRequestResponse messageInfo, int id) {
        this.helpers = helpers;
        this.messageInfo = messageInfo;
        this.id = id;

        // 解析请求
        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
        this.url = requestInfo.getUrl().toString();
        this.method = requestInfo.getMethod();

        // 解析响应
        byte[] responseBytes = messageInfo.getResponse();
        if (responseBytes != null) {
            IResponseInfo responseInfo = helpers.analyzeResponse(responseBytes);
            this.statusCode = responseInfo.getStatusCode();
        } else {
            this.statusCode = 0;
        }

        // 获取请求头和请求体
        byte[] requestBytes = messageInfo.getRequest();
        int requestBodyOffset = requestInfo.getBodyOffset();
        this.requestHeaders = new String(requestBytes, 0, requestBodyOffset).trim();
        this.requestBody = new String(requestBytes, requestBodyOffset, requestBytes.length - requestBodyOffset).trim();

        // 格式化请求头，确保正确显示
        if (!this.requestHeaders.contains("\n")) {
            this.requestHeaders = UrlUtil.formatHttpHeaders(this.requestHeaders);
        }

        // 获取响应体
        if (responseBytes != null) {
            IResponseInfo responseInfo = helpers.analyzeResponse(responseBytes);
            int responseBodyOffset = responseInfo.getBodyOffset();
            this.responseBody = new String(responseBytes, responseBodyOffset, responseBytes.length - responseBodyOffset).trim();

            // 尝试格式化JSON响应
            if (this.responseBody.trim().startsWith("{") && this.responseBody.trim().endsWith("}")) {
                try {
                    // 尝试美化JSON
                    this.responseBody = helpers.bytesToString(
                            helpers.stringToBytes(this.responseBody)
                    );
                } catch (Exception e) {
                    // 忽略格式化错误
                }
            }
        } else {
            this.responseBody = "";
        }
    }
}