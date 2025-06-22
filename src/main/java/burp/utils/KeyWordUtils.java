package burp.utils;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class KeyWordUtils {
    /**
     * 判断是否应该排除特定URL的请求，基于文件扩展名
     *
     * @param url 要检查的URL
     * @param extensions 要排除的扩展名，以逗号分隔
     * @return 如果应该排除则返回true，否则返回false
     */
    public static boolean shouldExcludeUrl(String url, String extensions) {
        if (url == null || url.isEmpty()) {
            return false;
        }
        
        // 检查文件扩展名
        if (extensions != null && !extensions.trim().isEmpty()) {
            String[] exts = extensions.split(",");
            for (String ext : exts) {
                ext = ext.trim().toLowerCase();
                if (!ext.isEmpty()) {
                    String lowerUrl = url.toLowerCase();
                    // 确保是真正的文件扩展名，而不是URL中间的部分
                    if (lowerUrl.endsWith("." + ext) || 
                        lowerUrl.contains("." + ext + "?") || 
                        lowerUrl.contains("." + ext + "#") ||
                        lowerUrl.contains("." + ext + "&")) {
                        log.info("URL包含扩展名 '" + ext + "' 被排除: " + url);
                        return true;
                    }
                }
            }
        }
        return false;
    }
    
    /**
     * 判断是否应该排除特定URL的请求，基于URL关键词
     *
     * @param url 要检查的URL
     * @param keywords 要排除的URL关键词，以逗号分隔
     * @return 如果应该排除则返回true，否则返回false
     */
    public static boolean shouldExcludeUrlByKeywords(String url, String keywords) {
        if (url == null || url.isEmpty()) {
            return false;
        }
        
        // 检查URL关键词
        if (keywords != null && !keywords.trim().isEmpty()) {
            String[] keywordArray = keywords.split(",");
            for (String keyword : keywordArray) {
                keyword = keyword.trim();
                if (!keyword.isEmpty()) {
                    if (url.toLowerCase().contains(keyword.toLowerCase())) {
                        log.info("URL包含关键词 '" + keyword + "' 被排除: " + url);
                        return true;
                    }
                }
            }
        }
        return false;
    }
}
