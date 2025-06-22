package burp.http;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import lombok.extern.slf4j.Slf4j;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

@Slf4j
public class HttpServiceUtil {
    private final IExtensionHelpers helpers;

    public HttpServiceUtil(IExtensionHelpers helpers) {
        this.helpers = helpers;
    }

    /**
     * 创建HTTP服务对象
     */
    private IHttpService createHttpService(String url) {
        try {
            URL parsedUrl = new URL(url);
            final String protocol = parsedUrl.getProtocol();
            final String host = parsedUrl.getHost();
            final int port = parsedUrl.getPort() != -1 ? parsedUrl.getPort() :
                    ("https".equalsIgnoreCase(protocol) ? 443 : 80);

            return new IHttpService() {
                @Override
                public String getHost() {
                    return host;
                }

                @Override
                public int getPort() {
                    return port;
                }

                @Override
                public String getProtocol() {
                    return protocol;
                }
            };
        } catch (Exception e) {
            log.error("创建HTTP服务对象时出错: " + url, e);
            return null;
        }
    }

    /**
     * 创建请求字节数组，确保正确处理各种字符编码
     */
    private byte[] createRequestBytes(String headers, String body) {
        try {
            // 解析头部为List<String>
            List<String> headersList = new ArrayList<>();
            String[] headerLines = headers.split("\\r?\\n");
            for (String header : headerLines) {
                if (!header.trim().isEmpty()) {
                    headersList.add(header);
                }
            }

            // 使用Burp Suite的API来正确构建HTTP消息
            byte[] bodyBytes = body != null ? body.getBytes("UTF-8") : new byte[0];
            return helpers.buildHttpMessage(headersList, bodyBytes);
        } catch (Exception e) {
            log.error("创建请求字节时出错: " + e.getMessage());
            // 出错时使用备用方法
            try {
                List<String> headersList = new ArrayList<>();
                String[] headerLines = headers.split("\\r?\\n");
                for (String header : headerLines) {
                    if (!header.trim().isEmpty()) {
                        headersList.add(header);
                    }
                }
                return helpers.buildHttpMessage(headersList, body != null ? body.getBytes() : new byte[0]);
            } catch (Exception ex) {
                log.error("备用方法也失败: " + ex.getMessage());
                // 最后的备用方法 - 直接返回原始头和体拼接
                String request = headers + "\r\n\r\n" + (body != null ? body : "");
                return request.getBytes();
            }
        }
    }

    /**
     * 获取HTTP状态码对应的文本描述
     */
    private String getStatusText(int statusCode) {
        switch (statusCode) {
            case 200:
                return "OK";
            case 201:
                return "Created";
            case 204:
                return "No Content";
            case 301:
                return "Moved Permanently";
            case 302:
                return "Found";
            case 400:
                return "Bad Request";
            case 401:
                return "Unauthorized";
            case 403:
                return "Forbidden";
            case 404:
                return "Not Found";
            case 405:
                return "Method Not Allowed";
            case 500:
                return "Internal Server Error";
            default:
                return "Unknown";
        }
    }


    /**
     * 创建响应字节数组
     */
    private byte[] createResponseBytes(int statusCode, String body) {
        String statusLine = "HTTP/1.1 " + statusCode + " " + getStatusText(statusCode) + "\r\n";
        String headers = "Content-Type: text/html; charset=utf-8\r\n" +
                "Content-Length: " + body.length() + "\r\n\r\n";
        String response = statusLine + headers + body;
        return response.getBytes();
    }

    /**
     * 创建一个临时的HTTP请求响应对象，并格式化请求头
     */
    public IHttpRequestResponse createFormattedHttpRequestResponse(String url, int statusCode,
                                                                   String requestHeaders, String requestBody,
                                                                   String responseBody) {
        // 创建HTTP服务
        IHttpService httpService = createHttpService(url);
        // 创建请求和响应字节
        byte[] requestBytes = createRequestBytes(requestHeaders, requestBody);
        byte[] responseBytes = createResponseBytes(statusCode, responseBody);

        // 返回HTTP请求响应对象
        return new DummyHttpRequestResponse(requestBytes, responseBytes, httpService);
    }

}
