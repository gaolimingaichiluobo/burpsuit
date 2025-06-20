package burp;

/**
 * 此接口用于表示活动扫描队列中的项目
 */
public interface IScanQueueItem
{
    /**
     * 获取此项目的URL
     * 
     * @return 项目的URL
     */
    String getUrl();
    
    /**
     * 获取此项目的状态
     * 
     * @return 项目的状态
     */
    String getStatus();
    
    /**
     * 获取此项目的问题数量
     * 
     * @return 项目的问题数量
     */
    int getNumErrors();
    
    /**
     * 获取此项目的问题
     * 
     * @return 项目的问题
     */
    IScanIssue[] getIssues();
    
    /**
     * 创建此项目的新扫描问题
     * 
     * @param issue 要添加的问题
     */
    void addScanIssue(IScanIssue issue);
    
    /**
     * 将此项目标记为已取消
     */
    void cancel();
    
    /**
     * 获取此项目的HTTP服务
     * 
     * @return 项目的HTTP服务
     */
    IHttpService getHttpService();
} 