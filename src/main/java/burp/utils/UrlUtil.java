package burp.utils;

import lombok.extern.slf4j.Slf4j;

import java.net.URL;
import java.util.*;

@Slf4j
public class UrlUtil {


    // 对URL进行过滤，移除参数部分
    public static String filterUrl(String url, boolean enableFilter, Map<String, String> urlFilterCache) {
        if (!enableFilter || url == null || !url.contains("?")) {
            return url;
        }

        // 检查缓存
        if (urlFilterCache.containsKey(url)) {
            return urlFilterCache.get(url);
        }

        String filteredUrl = url.substring(0, url.indexOf("?"));
        urlFilterCache.put(url, filteredUrl);
        log.info("URL参数过滤 - 原始URL: " + url);
        log.info("URL参数过滤 - 过滤后URL: " + filteredUrl);

        return filteredUrl;
    }
    /**
     * 从Burp Suite配置中加载设置
     */
    /**
     * 更新请求头中的Host和Cookie信息
     *
     * @param originalUrl   原始URL
     * @param newUrl        新URL
     * @param headers       原始请求头
     * @param updateHost    是否更新Host头
     * @param updateCookies 是否更新Cookie域
     * @param cookieDomain  新的Cookie域
     * @return 更新后的请求头
     */
    public static String updateRequestHeaders(String originalUrl, String newUrl, String headers,
                                              boolean updateHost, boolean updateCookies, String cookieDomain) {
        if (headers == null || headers.isEmpty()) {
            return headers;
        }

        try {
            // 解析原始URL和新URL
            URL parsedOriginalUrl = new URL(originalUrl);
            URL parsedNewUrl = new URL(newUrl);

            String originalHost = parsedOriginalUrl.getHost();
            int port = parsedOriginalUrl.getPort();
            String newHost = parsedNewUrl.getHost();

            // 如果请求头格式不正确，先格式化
            if (!headers.contains("\n") && !headers.contains("\r")) {
                headers = UrlUtil.formatHttpHeaders(headers);
            }

            // 按行分割
            String[] headerLines = headers.split("\\r?\\n");
            StringBuilder updatedHeaders = new StringBuilder();

            for (String line : headerLines) {
                // 处理Host头
                if (updateHost && line.toLowerCase().startsWith("host:")) {
                    String updatedHost = "Host: " + newHost;
                    // 如果新URL指定了非默认端口，也包含在Host头中
                    int newPort = parsedNewUrl.getPort();
                    if (newPort != -1) {
                        updatedHost += ":" + newPort;
                    }
                    updatedHeaders.append(updatedHost).append("\r\n");
                    log.info("更新Host头: " + line + " -> " + updatedHost);
                }
                // 处理Cookie头
                else if (updateCookies && line.toLowerCase().startsWith("cookie:") && !cookieDomain.isEmpty()) {
                    // 直接使用输入的cookieDomain作为新的Cookie值
                    String newCookieHeader = "Cookie: " + cookieDomain;
                    updatedHeaders.append(newCookieHeader).append("\r\n");
                    log.info("直接替换Cookie头: " + newCookieHeader);

                }
                //处理其他携带地址的头
                else if (line.toLowerCase().contains(originalHost)) {
                    String newOriginHeader = line.replace(originalHost, newHost).replace(Integer.toString(port), Integer.toString(parsedNewUrl.getPort()));
                    updatedHeaders.append(newOriginHeader).append("\r\n");
                } else {
                    // 保持其他头不变
                    updatedHeaders.append(line).append("\r\n");
                }
            }

            return updatedHeaders.toString();

        } catch (Exception e) {
            log.error("更新请求头时出错", e);
            return headers;  // 出错时返回原始头
        }
    }

    /**
     * 格式化HTTP请求头，使其更易读
     *
     * @param headers 原始请求头字符串
     * @return 格式化后的请求头
     */
    public static String formatHttpHeaders(String headers) {
        if (headers == null || headers.isEmpty()) {
            return "";
        }

        // 如果已经包含换行符，说明格式已经正确
        if (headers.contains("\n") || headers.contains("\r")) {
            return headers;
        }

        // 尝试识别HTTP请求/响应行和头部字段
        StringBuilder formatted = new StringBuilder();

        // 检查是否是HTTP请求或响应
        if (headers.startsWith("GET ") || headers.startsWith("POST ") ||
                headers.startsWith("PUT ") || headers.startsWith("DELETE ") ||
                headers.startsWith("HEAD ") || headers.startsWith("OPTIONS ") ||
                headers.startsWith("HTTP/")) {

            // 找到第一行（请求行或响应行）
            int httpVersionIndex = headers.indexOf(" HTTP/");
            if (httpVersionIndex > 0) {
                // 找到HTTP版本后面的空格位置
                int afterVersionIndex = headers.indexOf(" ", httpVersionIndex + 6);
                if (afterVersionIndex > 0) {
                    // 完整的请求行包括HTTP版本和版本号
                    String firstLine = headers.substring(0, afterVersionIndex);
                    formatted.append(firstLine).append("\r\n");
                    headers = headers.substring(afterVersionIndex + 1).trim();
                } else {
                    // 如果没有找到空格，可能是格式不标准，尝试其他方法
                    int spaceAfterPath = headers.indexOf(" ", headers.indexOf(" ") + 1);
                    if (spaceAfterPath > 0) {
                        // 找到路径后的空格
                        int versionEnd = headers.indexOf(" ", spaceAfterPath + 6); // HTTP/1.1 后的空格
                        if (versionEnd > 0) {
                            String firstLine = headers.substring(0, versionEnd);
                            formatted.append(firstLine).append("\r\n");
                            headers = headers.substring(versionEnd + 1).trim();
                        }
                    }
                }
            } else {
                // 可能是响应行或其他格式
                // 尝试查找第一个头部字段的开始位置
                int firstHeaderStart = -1;
                String[] commonHeaders = {"Host:", "User-Agent:", "Accept:", "Content-Type:", "Cookie:"};
                for (String header : commonHeaders) {
                    int index = headers.indexOf(header);
                    if (index > 0 && (firstHeaderStart == -1 || index < firstHeaderStart)) {
                        firstHeaderStart = index;
                    }
                }

                if (firstHeaderStart > 0) {
                    // 找到了第一个头部字段
                    String firstLine = headers.substring(0, firstHeaderStart).trim();
                    formatted.append(firstLine).append("\r\n");
                    headers = headers.substring(firstHeaderStart).trim();
                }
            }
        }

        // 使用更智能的方式处理头部字段
        // 常见的HTTP头部字段名
        String[] commonHeaderNames = {
                "Host:", "User-Agent:", "Accept:", "Accept-Language:", "Accept-Encoding:",
                "Connection:", "Content-Type:", "Content-Length:", "Cookie:", "Referer:",
                "Origin:", "Authorization:", "X-Requested-With:", "X-Forwarded-For:",
                "Sec-Ch-Ua:", "Sec-Ch-Ua-Mobile:", "Sec-Ch-Ua-Platform:", "Upgrade-Insecure-Requests:",
                "Sec-Fetch-Site:", "Sec-Fetch-Mode:", "Sec-Fetch-Dest:", "Sec-Fetch-User:"
        };

        // 查找所有头部字段的位置
        List<Integer> headerPositions = new ArrayList<>();
        for (String headerName : commonHeaderNames) {
            int pos = 0;
            while ((pos = headers.indexOf(headerName, pos)) >= 0) {
                // 确保这是一个头部字段的开始，而不是值的一部分
                if (pos == 0 || Character.isWhitespace(headers.charAt(pos - 1))) {
                    headerPositions.add(pos);
                }
                pos += headerName.length();
            }
        }
        // 按位置排序
        Collections.sort(headerPositions);
        // 如果没有找到任何头部字段，尝试使用空格分割
        if (headerPositions.isEmpty()) {
            String[] parts = headers.split(" ");
            StringBuilder currentHeader = new StringBuilder();

            for (String part : parts) {
                if (part.isEmpty()) continue;

                // 检查是否是新的头部字段
                if (part.endsWith(":")) {
                    // 如果当前已有内容，先添加到结果中
                    if (!currentHeader.isEmpty()) {
                        formatted.append(currentHeader).append("\r\n");
                        currentHeader = new StringBuilder();
                    }
                    currentHeader.append(part).append(" ");
                } else if (part.contains(":") && currentHeader.isEmpty()) {
                    // 这可能是一个完整的头部字段
                    currentHeader.append(part);
                    formatted.append(currentHeader.toString()).append("\r\n");
                    currentHeader = new StringBuilder();
                } else {
                    // 继续当前头部字段的值
                    currentHeader.append(part).append(" ");
                }
            }

            // 添加最后一个头部字段
            if (!currentHeader.isEmpty()) {
                formatted.append(currentHeader).append("\r\n");
            }
        } else {
            // 根据找到的头部字段位置分割
            for (int i = 0; i < headerPositions.size(); i++) {
                int start = headerPositions.get(i);
                int end = (i < headerPositions.size() - 1) ? headerPositions.get(i + 1) : headers.length();

                // 提取头部字段
                String header = headers.substring(start, end).trim();
                formatted.append(header).append("\r\n");
            }
        }

        return formatted.toString();
    }


    /**
     * 替换URL中的主机和端口
     */
    public static String replaceHostAndPort(String url, String newHost, String newPort) {
        try {
            URL parsedUrl = new URL(url);
            String protocol = parsedUrl.getProtocol();
            String path = parsedUrl.getPath();
            String query = parsedUrl.getQuery();

            String newUrl = protocol + "://" + newHost + ":" + newPort;
            if (path != null && !path.isEmpty()) {
                newUrl += path;
            }
            if (query != null && !query.isEmpty()) {
                newUrl += "?" + query;
            }

            log.info("URL替换: " + url + " -> " + newUrl);
            return newUrl;
        } catch (Exception e) {
            log.error("替换URL主机和端口时出错: " + url, e);
            return url;
        }
    }

    /**
     * 仅替换URL中的主机
     */
    public static String replaceHost(String url, String newHost) {
        try {
            URL parsedUrl = new URL(url);
            String protocol = parsedUrl.getProtocol();
            int port = parsedUrl.getPort();
            String path = parsedUrl.getPath();
            String query = parsedUrl.getQuery();

            String newUrl = protocol + "://" + newHost;
            if (port != -1) {
                newUrl += ":" + port;
            }
            if (path != null && !path.isEmpty()) {
                newUrl += path;
            }
            if (query != null && !query.isEmpty()) {
                newUrl += "?" + query;
            }

            log.info("主机替换: " + url + " -> " + newUrl);
            return newUrl;
        } catch (Exception e) {
            log.error("替换URL主机时出错: " + url, e);
            return url;
        }
    }

    /**
     * 仅替换URL中的端口
     */
    public static String replacePort(String url, String newPort) {
        try {
            URL parsedUrl = new URL(url);
            String protocol = parsedUrl.getProtocol();
            String host = parsedUrl.getHost();
            String path = parsedUrl.getPath();
            String query = parsedUrl.getQuery();

            String newUrl = protocol + "://" + host + ":" + newPort;
            if (path != null && !path.isEmpty()) {
                newUrl += path;
            }
            if (query != null && !query.isEmpty()) {
                newUrl += "?" + query;
            }

            log.info("端口替换: " + url + " -> " + newUrl);
            return newUrl;
        } catch (Exception e) {
            log.error("替换URL端口时出错: " + url, e);
            return url;
        }
    }

    /**
     * 对URL进行规范化处理，用于去重
     * 默认移除参数部分以实现更好的去重效果
     *
     * @param url 原始URL
     * @return 规范化后的URL
     */
    public static String normalizeUrlForDeduplication(String url) {
        if (url == null) {
            return "";
        }
        String normalizedUrl = url;
        // 移除URL参数
        if (normalizedUrl.contains("?")) {
            normalizedUrl = normalizedUrl.substring(0, normalizedUrl.indexOf("?"));
        }
        // 移除URL片段标识符(#)
        if (normalizedUrl.contains("#")) {
            normalizedUrl = normalizedUrl.substring(0, normalizedUrl.indexOf("#"));
        }
        // 标准化末尾的斜杠
        if (normalizedUrl.endsWith("/")) {
            normalizedUrl = normalizedUrl.substring(0, normalizedUrl.length() - 1);
        }
        // 添加URL规范化调试日志
        log.info("URL规范化: " + url + " -> " + normalizedUrl);
        return normalizedUrl;
    }
}
