package burp;

/**
 * 此接口用于接收有关扩展状态变化的通知
 */
public interface IExtensionStateListener
{
    /**
     * 当扩展被卸载时调用此方法
     */
    void extensionUnloaded();
} 