package burp;

/**
 * 所有扩展必须实现的接口
 */
public interface IBurpExtender
{
    /**
     * 当扩展被加载时Burp会调用此方法
     * 
     * @param callbacks 提供一组回调方法，扩展可以通过这些方法执行各种操作
     */
    void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks);
} 