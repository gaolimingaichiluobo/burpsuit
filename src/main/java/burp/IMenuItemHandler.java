package burp;

/**
 * 此接口用于处理自定义上下文菜单项的点击事件
 */
public interface IMenuItemHandler
{
    /**
     * 当用户点击菜单项时调用此方法
     * 
     * @param menuItemCaption 被点击的菜单项标题
     * @param messageInfo 与菜单项关联的HTTP请求/响应
     */
    void menuItemClicked(String menuItemCaption, IHttpRequestResponse[] messageInfo);
} 