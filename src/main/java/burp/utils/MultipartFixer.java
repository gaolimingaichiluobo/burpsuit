package burp.utils;

import lombok.extern.slf4j.Slf4j;

import java.util.regex.*;
import java.util.*;

@Slf4j
public class MultipartFixer {

    /**
     * 主入口：判断内容是否是 multipart 格式，如果是则尝试修复
     */
    public static String fixIfMultipart(String rawContent) {
        if (!isLikelyMultipart(rawContent)) {
            return rawContent; // 内容不像 multipart，直接返回原样
        }

        String boundary = extractBoundary(rawContent);
        if (boundary == null) {
            return rawContent; // 找不到 boundary，返回原样
        }

        return fixMultipart(rawContent, boundary);
    }

    /**
     * 判断内容是否看起来是 multipart/form-data 格式（不依赖 Content-Type）
     */
    public static boolean isLikelyMultipart(String content) {
        if (content == null || content.length() < 100) return false;

        // 方式一：包含 WebKitFormBoundary（浏览器生成格式）
        if (content.contains("WebKitFormBoundary")) return true;

        // 方式二：通用 boundary 格式
        Pattern boundaryPattern = Pattern.compile("(-{6,}[a-zA-Z0-9_-]+)");
        Matcher matcher = boundaryPattern.matcher(content);

        int boundaryCount = 0;
        Set<String> boundarySet = new HashSet<>();

        while (matcher.find()) {
            boundaryCount++;
            boundarySet.add(matcher.group(1));
        }

        boolean looksLikeFormField = content.contains("name=");

        return boundarySet.size() == 1 && boundaryCount >= 2 && looksLikeFormField;
    }

    /**
     * 从内容中提取 boundary（以 ------ 开头）
     */
    public static String extractBoundary(String content) {
        Pattern boundaryPattern = Pattern.compile("(-{6,}[a-zA-Z0-9_-]+)");
        Matcher matcher = boundaryPattern.matcher(content);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    /**
     * 修复 multipart 内容的结构（添加换行、分段、头部）
     */
    public static String fixMultipart(String content, String boundary) {
        String[] rawParts = content.split("(?=" + Pattern.quote(boundary) + ")");
        StringBuilder result = new StringBuilder();

        for (String part : rawParts) {
            part = part.trim();
            if (part.isEmpty()) continue;

            if (part.endsWith("--")) {
                result.append(boundary).append("--\r\n");
                continue;
            }

            // 1. 标准格式：含 Content-Disposition
            Pattern fullPattern = Pattern.compile(
                    Pattern.quote(boundary) + "\\s*Content-Disposition:\\s*form-data;\\s*name=\"(.*?)\"\\s+(.*)",
                    Pattern.DOTALL
            );
            Matcher fullMatcher = fullPattern.matcher(part);

            if (fullMatcher.find()) {
                String name = fullMatcher.group(1).trim();
                String value = fullMatcher.group(2).trim();
                result.append(boundary).append("\r\n");
                result.append("Content-Disposition: form-data; name=\"").append(name).append("\"\r\n\r\n");
                result.append(value).append("\r\n");
                continue;
            }

            // 2. 简化格式：只含 name=，没有 Content-Disposition
            Pattern fallbackPattern = Pattern.compile("name=\"(.*?)\"\\s+(.*)", Pattern.DOTALL);
            Matcher fallbackMatcher = fallbackPattern.matcher(part);
            if (fallbackMatcher.find()) {
                String name = fallbackMatcher.group(1).trim();
                String value = fallbackMatcher.group(2).trim();
                result.append(boundary).append("\r\n");
                result.append("Content-Disposition: form-data; name=\"").append(name).append("\"\r\n\r\n");
                result.append(value).append("\r\n");
                continue;
            }

            // 3. 无法解析，保留原始内容
            result.append(part).append("\r\n");
        }
        return result.toString();
    }
}
