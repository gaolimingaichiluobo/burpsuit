package burp;

import java.awt.Component;
import java.io.OutputStream;
import java.util.Map;
import java.util.List;

/**
 * Burp Suite扩展回调接口
 */
public interface IBurpExtenderCallbacks
{
    // 工具标识常量
    int TOOL_SUITE = 0x1;
    int TOOL_TARGET = 0x2;
    int TOOL_PROXY = 0x4;
    int TOOL_SPIDER = 0x8;
    int TOOL_SCANNER = 0x10;
    int TOOL_INTRUDER = 0x20;
    int TOOL_REPEATER = 0x40;
    int TOOL_SEQUENCER = 0x80;
    int TOOL_DECODER = 0x100;
    int TOOL_COMPARER = 0x200;
    int TOOL_EXTENDER = 0x400;
    
    /**
     * 设置扩展名称，显示在UI中
     */
    void setExtensionName(String name);
    
    /**
     * 注册HTTP监听器
     */
    void registerHttpListener(IHttpListener listener);
    
    /**
     * 获取Burp的帮助类
     */
    IExtensionHelpers getHelpers();
    
    /**
     * 自定义UI组件
     */
    void customizeUiComponent(Component component);
    
    /**
     * 向Burp UI添加新的标签页
     */
    void addSuiteTab(ITab tab);
    
    /**
     * 将请求和响应缓冲区保存到临时文件，返回可以从中检索内容的新请求/响应对象
     * 此方法用于处理大型请求和响应，避免内存问题
     * 
     * @param httpRequestResponse 包含要保存的缓冲区的请求/响应对象
     * @return 包含指向已保存缓冲区的指针的新请求/响应对象
     */
    IHttpRequestResponse saveBuffersToTempFiles(IHttpRequestResponse httpRequestResponse);
    
    /**
     * 向指定HTTP服务发送HTTP请求并检索响应
     * 
     * @param httpService 用于发送请求的HTTP服务
     * @param request 请求内容
     * @return 包含请求和响应的对象
     */
    IHttpRequestResponse makeHttpRequest(IHttpService httpService, byte[] request);
    
    /**
     * 获取代理历史记录
     * 
     * @return 代理历史记录中的项目列表
     */
    List<IHttpRequestResponse> getProxyHistory();
    
    /**
     * 获取站点地图
     * 
     * @return 站点地图中的项目列表
     */
    List<IHttpRequestResponse> getSiteMap(String urlPrefix);
    
    /**
     * 获取扫描问题
     * 
     * @return 扫描问题列表
     */
    List<IScanIssue> getScanIssues(String urlPrefix);
    
    /**
     * 向目标站点地图添加一个新的扫描问题
     * 
     * @param issue 要添加的扫描问题
     */
    void addScanIssue(IScanIssue issue);
    
    /**
     * 注册扫描器监听器
     */
    void registerScannerListener(IScannerListener listener);
    
    /**
     * 注册上下文菜单工厂
     */
    void registerContextMenuFactory(IContextMenuFactory factory);
    
    /**
     * 注册消息编辑器标签工厂
     */
    void registerMessageEditorTabFactory(IMessageEditorTabFactory factory);
    
    /**
     * 注册会话处理操作
     */
    void registerSessionHandlingAction(ISessionHandlingAction action);
    
    /**
     * 注册代理监听器
     */
    void registerProxyListener(IProxyListener listener);
    
    /**
     * 注册扩展状态监听器
     */
    void registerExtensionStateListener(IExtensionStateListener listener);
    
    /**
     * 移除扩展状态监听器
     */
    void removeExtensionStateListener(IExtensionStateListener listener);
    
    /**
     * 获取标准输出流
     */
    OutputStream getStdout();
    
    /**
     * 获取标准错误流
     */
    OutputStream getStderr();
    
    /**
     * 获取Burp的配置设置
     */
    String[] getBurpVersion();
    
    /**
     * 获取当前请求的命令行参数
     */
    String[] getCommandLineArguments();
    
    /**
     * 保存扩展设置
     */
    void saveExtensionSetting(String name, String value);
    
    /**
     * 加载扩展设置
     */
    String loadExtensionSetting(String name);
    
    /**
     * 创建临时文件
     */
    String getExtensionFilename();
    
    /**
     * 是否在扩展中运行
     */
    boolean isExtensionBapp();
    
    /**
     * 移除扫描监听器
     */
    void removeSuiteTab(ITab tab);
    
    /**
     * 自定义工具提示
     */
    void setToolTipText(Component component, String text);
    
    /**
     * 发出系统通知
     */
    void issueAlert(String message);

//    void registerScannerCheck(CustomVulnerabilityScanner vulnerabilityScanner);

    IHttpRequestResponse applyMarkers(IHttpRequestResponse baseRequestResponse, Object o, Object o1);
} 