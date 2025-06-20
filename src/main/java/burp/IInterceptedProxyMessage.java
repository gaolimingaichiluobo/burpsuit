package burp;

/**
 * 此接口用于表示被Burp代理工具拦截的HTTP消息
 */
public interface IInterceptedProxyMessage
{
    /**
     * 获取消息引用号
     * 
     * @return 消息引用号
     */
    int getMessageReference();
    
    /**
     * 获取代理工具监听器端口
     * 
     * @return 代理工具监听器端口
     */
    int getListenerPort();
    
    /**
     * 获取客户端IP地址
     * 
     * @return 客户端IP地址
     */
    String getClientIpAddress();
    
    /**
     * 获取原始请求
     * 
     * @return 原始请求
     */
    IHttpRequestResponse getMessageInfo();
    
    /**
     * 设置是否拦截此消息
     * 
     * @param intercept 如果消息应被拦截则为true，否则为false
     */
    void setInterceptAction(int intercept);
    
    /**
     * 获取当前拦截动作
     * 
     * @return 当前拦截动作
     */
    int getInterceptAction();
    
    /**
     * 常量：允许消息继续而不进行修改
     */
    static final int ACTION_FOLLOW_RULES = 0;
    
    /**
     * 常量：不拦截消息
     */
    static final int ACTION_DONT_INTERCEPT = 1;
    
    /**
     * 常量：拦截消息
     */
    static final int ACTION_DO_INTERCEPT = 2;
    
    /**
     * 常量：丢弃消息
     */
    static final int ACTION_DROP = 3;
} 