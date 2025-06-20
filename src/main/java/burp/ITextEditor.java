package burp;

import java.awt.Component;

/**
 * 此接口用于操作Burp的原始文本编辑器
 */
public interface ITextEditor
{
    /**
     * 获取编辑器组件
     * 
     * @return 编辑器组件
     */
    Component getComponent();
    
    /**
     * 获取编辑器内容
     * 
     * @return 编辑器内容
     */
    byte[] getText();
    
    /**
     * 设置编辑器内容
     * 
     * @param text 要设置的内容
     */
    void setText(byte[] text);
    
    /**
     * 获取选中的文本
     * 
     * @return 选中的文本
     */
    byte[] getSelectedText();
    
    /**
     * 获取选择的偏移量
     * 
     * @return 包含选择起始和结束偏移量的数组
     */
    int[] getSelectionBounds();
    
    /**
     * 设置选择范围
     * 
     * @param start 选择的起始偏移量
     * @param end 选择的结束偏移量
     */
    void setSelectionBounds(int start, int end);
    
    /**
     * 检查编辑器内容是否已被修改
     * 
     * @return 如果内容已被修改则为true
     */
    boolean isModified();
    
    /**
     * 设置编辑器的搜索表达式
     * 
     * @param expression 搜索表达式
     */
    void setSearchExpression(String expression);
} 