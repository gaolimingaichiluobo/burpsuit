package burp;

import javax.swing.JMenuItem;
import java.util.List;

/**
 * 此接口用于创建上下文菜单项
 */
public interface IContextMenuFactory
{
    /**
     * 创建上下文菜单项
     * 
     * @param invocation 包含调用上下文菜单的详细信息
     * @return 要显示的菜单项列表
     */
    List<JMenuItem> createMenuItems(IContextMenuInvocation invocation);
} 