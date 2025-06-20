package burp;

/**
 * 此接口用于控制消息编辑器
 */
public interface IMessageEditorController
{
    /**
     * 获取HTTP服务信息
     * 
     * @return HTTP服务信息
     */
    IHttpService getHttpService();
    
    /**
     * 获取请求内容
     * 
     * @return 请求内容
     */
    byte[] getRequest();
    
    /**
     * 获取响应内容
     * 
     * @return 响应内容
     */
    byte[] getResponse();
} 