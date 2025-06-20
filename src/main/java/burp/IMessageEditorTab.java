package burp;

import java.awt.Component;

/**
 * 此接口用于自定义消息编辑器标签
 */
public interface IMessageEditorTab
{
    /**
     * 获取标签的UI组件
     * 
     * @return 标签的UI组件
     */
    Component getUiComponent();
    
    /**
     * 获取标签的标题
     * 
     * @return 标签的标题
     */
    String getTabCaption();
    
    /**
     * 设置消息
     * 
     * @param content 消息内容
     * @param isRequest 是否为请求消息
     * @return 是否应该显示此标签
     */
    boolean isEnabled(byte[] content, boolean isRequest);
    
    /**
     * 设置消息
     * 
     * @param content 消息内容
     * @param isRequest 是否为请求消息
     */
    void setMessage(byte[] content, boolean isRequest);
    
    /**
     * 获取消息
     * 
     * @return 消息内容
     */
    byte[] getMessage();
    
    /**
     * 判断消息是否被修改
     * 
     * @return 如果消息被修改则返回true
     */
    boolean isModified();
    
    /**
     * 获取选中的数据
     * 
     * @return 选中的数据
     */
    byte[] getSelectedData();
} 