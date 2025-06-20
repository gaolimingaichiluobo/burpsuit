package burp;

/**
 * 此接口用于创建消息编辑器标签
 */
public interface IMessageEditorTabFactory
{
    /**
     * 创建一个新的消息编辑器标签
     * 
     * @param controller 消息编辑器控制器
     * @param editable 标签是否可编辑
     * @return 新创建的消息编辑器标签
     */
    IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable);
} 