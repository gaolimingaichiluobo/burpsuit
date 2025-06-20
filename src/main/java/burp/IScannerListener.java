package burp;

/**
 * 此接口用于接收有关新扫描问题的通知
 */
public interface IScannerListener
{
    /**
     * 当发现新的扫描问题时调用此方法
     * 
     * @param issue 发现的扫描问题
     */
    void newScanIssue(IScanIssue issue);
} 