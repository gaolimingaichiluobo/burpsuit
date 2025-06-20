package burp;

/**
 * 此接口用于自定义会话处理操作
 */
public interface ISessionHandlingAction
{
    /**
     * 获取操作名称
     * 
     * @return 操作名称
     */
    String getActionName();
    
    /**
     * 执行会话处理操作
     * 
     * @param currentRequest 当前请求信息
     * @param macroItems 宏项目
     */
    void performAction(IHttpRequestResponse currentRequest, IHttpRequestResponse[] macroItems);
} 