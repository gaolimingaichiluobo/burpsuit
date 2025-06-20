package burp;

/**
 * 此接口用于HTTP请求和响应的详细信息
 */
public interface IHttpRequestResponse
{
    /**
     * 获取请求的内容
     * 
     * @return 请求的字节数组
     */
    byte[] getRequest();
    
    /**
     * 获取响应的内容
     * 
     * @return 响应的字节数组
     */
    byte[] getResponse();
    
    /**
     * 获取发送请求的HTTP服务信息
     * 
     * @return HTTP服务对象
     */
    IHttpService getHttpService();
} 