package burp;

/**
 * 此接口用于提供HTTP服务详情
 */
public interface IHttpService
{
    /**
     * 获取服务主机名
     * 
     * @return 服务主机名
     */
    String getHost();
    
    /**
     * 获取服务端口
     * 
     * @return 服务端口
     */
    int getPort();
    
    /**
     * 获取服务协议
     * 
     * @return 服务协议
     */
    String getProtocol();
} 