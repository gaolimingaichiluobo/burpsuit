package burp;

import java.net.URL;

/**
 * 此接口用于表示Burp Scanner工具发现的问题
 */
public interface IScanIssue
{
    /**
     * 获取问题的URL
     * 
     * @return 问题的URL
     */
    URL getUrl();
    
    /**
     * 获取问题的类型
     * 
     * @return 问题的类型
     */
    String getIssueName();
    
    /**
     * 获取问题的严重程度
     *
     * @return 问题的严重程度
     */
    String getSeverity();
    
    /**
     * 获取问题的置信度
     *
     * @return 问题的置信度
     */
    String getConfidence();
    
    /**
     * 获取问题的详细描述
     * 
     * @return 问题的详细描述
     */
    String getIssueDetail();
    
    /**
     * 获取问题的背景信息
     * 
     * @return 问题的背景信息
     */
    String getIssueBackground();
    
    /**
     * 获取修复建议
     * 
     * @return 修复建议
     */
    String getRemediationDetail();
    
    /**
     * 获取修复背景信息
     * 
     * @return 修复背景信息
     */
    String getRemediationBackground();
    
    /**
     * 获取与问题相关的HTTP消息
     * 
     * @return HTTP消息数组
     */
    IHttpRequestResponse[] getHttpMessages();
    
    /**
     * 获取与问题相关的HTTP服务
     * 
     * @return HTTP服务信息
     */
    IHttpService getHttpService();
    
    /**
     * 获取问题类型
     * 
     * @return 问题类型（数值表示）
     */
    int getIssueType();
} 