package burp;

/**
 * 此接口用于接收代理工具捕获的HTTP消息通知
 */
public interface IProxyListener
{
    /**
     * 当Burp代理工具捕获到HTTP消息时调用此方法
     * 
     * @param messageIsRequest 如果消息是请求则为true，如果是响应则为false
     * @param message 包含请求/响应详情的对象
     */
    void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message);
} 