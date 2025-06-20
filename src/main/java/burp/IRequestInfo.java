package burp;

import java.net.URL;
import java.util.List;

/**
 * 此接口用于获取HTTP请求的详细信息
 */
public interface IRequestInfo
{
    // 请求内容类型常量
    byte CONTENT_TYPE_NONE = 0;
    byte CONTENT_TYPE_URL_ENCODED = 1;
    byte CONTENT_TYPE_MULTIPART = 2;
    byte CONTENT_TYPE_XML = 3;
    byte CONTENT_TYPE_JSON = 4;
    byte CONTENT_TYPE_AMF = 5;
    byte CONTENT_TYPE_UNKNOWN = -1;
    
    /**
     * 获取请求中使用的HTTP方法
     * 
     * @return HTTP方法，如"GET"或"POST"
     */
    String getMethod();
    
    /**
     * 获取请求URL
     * 
     * @return 请求URL
     */
    URL getUrl();
    
    /**
     * 获取请求正文部分在请求消息中的偏移量
     * 
     * @return 请求正文的偏移量
     */
    int getBodyOffset();
    
    /**
     * 获取请求中的所有HTTP头
     * 
     * @return HTTP头列表
     */
    List<String> getHeaders();
    
    /**
     * 获取请求参数
     * 
     * @return 请求参数列表
     */
    List<IParameter> getParameters();
    
    /**
     * 获取请求的内容类型
     * 
     * @return 内容类型，使用上面定义的常量
     */
    byte getContentType();
    
    /**
     * 获取HTTP版本
     * 
     * @return HTTP版本
     */
    String getHttpVersion();
} 