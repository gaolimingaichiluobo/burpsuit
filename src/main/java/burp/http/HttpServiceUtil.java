package burp.http;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;
import lombok.extern.slf4j.Slf4j;

import java.net.URL;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
     * 替换请求中的会话信息（Cookie/Authorization）
     *
     * @param request 原始请求
     * @param session 会话信息字符串
     * @return 替换后的请求
     */
    public byte[] replaceSessionInRequest(byte[] request, String session) {
        if (session == null || session.trim().isEmpty()) return request;

        try {
            IRequestInfo requestInfo = helpers.analyzeRequest(request);
            List<String> headers = requestInfo.getHeaders();
            List<String> newHeaders = new ArrayList<>();

            // 提取 Cookie 和 Authorization
            Map<String, String> cookieMap = new HashMap<>();
            String authHeader = extractHeader(session, "Authorization");

            // 提取 Cookie 到 Map
            String cookieHeader = extractHeader(session, "Cookie");
            if (cookieHeader != null) {
                String cookieValue = cookieHeader.substring("Cookie:".length()).trim();
                for (String cookie : cookieValue.split(";")) {
                    cookie = cookie.trim();
                    if (cookie.isEmpty()) continue;
                    String[] parts = cookie.split("=", 2);
                    cookieMap.put(parts[0], parts.length > 1 ? parts[1] : "");
                }
            }

            boolean cookieReplaced = false;
            boolean authReplaced = false;

            for (String header : headers) {
                String lower = header.toLowerCase();
                if (lower.startsWith("cookie:") && !cookieMap.isEmpty()) {
                    newHeaders.add(buildCookieHeader(cookieMap));
                    cookieReplaced = true;
                    log.info("已替换Cookie");
                } else if (lower.startsWith("authorization:") && authHeader != null) {
                    newHeaders.add(authHeader);
                    authReplaced = true;
                    log.info("已替换Authorization");
                } else {
                    newHeaders.add(header);
                }
            }

            // 没有则添加
            if (!cookieReplaced && !cookieMap.isEmpty()) {
                newHeaders.add(buildCookieHeader(cookieMap));
                log.info("已添加新Cookie");
            }
            if (!authReplaced && authHeader != null) {
                newHeaders.add(authHeader);
                log.info("已添加新Authorization");
            }

            // 重新构建请求
            byte[] body = Arrays.copyOfRange(request, requestInfo.getBodyOffset(), request.length);
            return helpers.buildHttpMessage(newHeaders, body);

        } catch (Exception e) {
            log.error("替换会话信息出错: " + e.getMessage(), e);
            return request;
        }
    }

    private String buildCookieHeader(Map<String, String> cookieMap) {
        StringBuilder sb = new StringBuilder("Cookie: ");
        boolean first = true;
        for (Map.Entry<String, String> entry : cookieMap.entrySet()) {
            if (!first) sb.append("; ");
            sb.append(entry.getKey());
            if (!entry.getValue().isEmpty()) {
                sb.append("=").append(entry.getValue());
            }
            first = false;
        }
        return sb.toString();
    }

    private String extractHeader(String session, String key) {
        Pattern pattern = Pattern.compile("(?i)^" + key + ":(.*?)$", Pattern.MULTILINE);
        Matcher matcher = pattern.matcher(session);
        if (matcher.find()) {
            return key + ":" + matcher.group(1).trim();
        }
        return null;
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
