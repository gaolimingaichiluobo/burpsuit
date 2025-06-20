package burp;

import java.util.List;

/**
 * 此接口用于获取HTTP响应的详细信息
 */
public interface IResponseInfo
{
    /**
     * 获取响应的HTTP状态码
     * 
     * @return HTTP状态码
     */
    short getStatusCode();
    
    /**
     * 获取响应正文部分在响应消息中的偏移量
     * 
     * @return 响应正文的偏移量
     */
    int getBodyOffset();
    
    /**
     * 获取响应中的所有HTTP头
     * 
     * @return HTTP头列表
     */
    List<String> getHeaders();
    
    /**
     * 获取响应的MIME类型
     * 
     * @return 响应的MIME类型
     */
    String getStatedMimeType();
    
    /**
     * 获取通过内容分析推断的MIME类型
     * 
     * @return 推断的MIME类型
     */
    String getInferredMimeType();
    
    /**
     * 检查响应是否截断
     * 
     * @return 如果响应被截断则返回true
     */
    boolean isResponseTruncated();
    
    /**
     * 获取HTTP响应状态消息
     * 
     * @return HTTP响应状态消息
     */
    String getStatusMessage();
    
    /**
     * 获取HTTP版本
     * 
     * @return HTTP版本
     */
    String getHttpVersion();
    
    /**
     * 获取Cookie参数
     * 
     * @return Cookie参数列表
     */
    List<ICookie> getCookies();
} 