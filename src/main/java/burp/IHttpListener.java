package burp;

/**
 * 此接口用于接收有关HTTP请求和响应的通知
 */
public interface IHttpListener
{
    /**
     * 当Burp工具发出HTTP请求或收到HTTP响应时调用此方法
     * 
     * @param toolFlag 标识发出请求的Burp工具
     * @param messageIsRequest 如果消息是请求则为true，如果是响应则为false
     * @param messageInfo 包含请求/响应详情的对象
     */
    void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo);
} 