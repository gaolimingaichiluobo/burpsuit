package burp;

/**
 * 此接口用于提供上下文菜单调用的详细信息
 */
public interface IContextMenuInvocation
{
    // 上下文类型常量
    byte CONTEXT_MESSAGE_EDITOR_REQUEST = 0;
    byte CONTEXT_MESSAGE_EDITOR_RESPONSE = 1;
    byte CONTEXT_MESSAGE_VIEWER_REQUEST = 2;
    byte CONTEXT_MESSAGE_VIEWER_RESPONSE = 3;
    byte CONTEXT_TARGET_SITE_MAP_TREE = 4;
    byte CONTEXT_TARGET_SITE_MAP_TABLE = 5;
    byte CONTEXT_PROXY_HISTORY = 6;
    byte CONTEXT_SCANNER_RESULTS = 7;
    byte CONTEXT_INTRUDER_PAYLOAD_POSITIONS = 8;
    byte CONTEXT_INTRUDER_ATTACK_RESULTS = 9;
    byte CONTEXT_SEARCH_RESULTS = 10;
    
    /**
     * 获取调用上下文的工具
     * 
     * @return 工具标识
     */
    int getToolFlag();
    
    /**
     * 获取调用上下文
     * 
     * @return 上下文类型，使用上面定义的常量
     */
    byte getInvocationContext();
    
    /**
     * 获取选中的消息
     * 
     * @return 选中的HTTP消息
     */
    IHttpRequestResponse[] getSelectedMessages();
    
    /**
     * 获取选中的文本
     * 
     * @return 选中的文本
     */
    byte[] getSelectedMessage();
    
    /**
     * 获取选中文本的边界
     * 
     * @return 包含选中文本起始和结束偏移量的数组
     */
    int[] getSelectionBounds();
} 