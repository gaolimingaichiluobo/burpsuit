package burp;

import java.awt.Component;

/**
 * 此接口用于自定义Burp Suite UI的标签页
 */
public interface ITab
{
    /**
     * 获取此标签页的标题
     * 
     * @return 标签页标题
     */
    String getTabCaption();
    
    /**
     * 获取此标签页的组件
     * 
     * @return 标签页组件
     */
    Component getUiComponent();
} 