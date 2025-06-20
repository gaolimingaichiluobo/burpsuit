package burp.model;

import burp.result.PrivilegeEscalationResult;
import lombok.extern.slf4j.Slf4j;

import javax.swing.table.AbstractTableModel;
import java.util.List;

/**
 * 越权测试表格模型
 */
@Slf4j
public class PrivilegeEscalationTableModel extends AbstractTableModel {
    private final String[] columnNames = {"选择", "序号", "URL", "测试类型", "测试内容", "原始会话", "测试会话", "原始状态码", "测试状态码", "测试结果"};

    private final List<PrivilegeEscalationResult> privilegeEscalationResults;

    public PrivilegeEscalationTableModel(List<PrivilegeEscalationResult> privilegeEscalationResults) {
        this.privilegeEscalationResults = privilegeEscalationResults;
    }

    @Override
    public int getRowCount() {
        return privilegeEscalationResults.size();
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public String getColumnName(int column) {
        return columnNames[column];
    }

    @Override
    public Class<?> getColumnClass(int column) {
        if (column == 0) {
            return Boolean.class;
        } else if (column == 1 || column == 7 || column == 8) {
            return Integer.class;
        } else {
            return String.class;
        }
    }

    @Override
    public boolean isCellEditable(int row, int column) {
        return column == 0; // 仅允许修改选择框
    }

    @Override
    public Object getValueAt(int row, int column) {
        PrivilegeEscalationResult result = privilegeEscalationResults.get(row);
        switch (column) {
            case 0:
                return result.isSelected();
            case 1:
                return result.getId();
            case 2:
                return result.getUrl(); // 这里应该返回已过滤的URL
            case 3:
                return result.getTestType();
            case 4:
                return result.getParamName();
            case 5:
                return result.getOriginalSession() != null ? result.getOriginalSession().getName() : "";
            case 6:
                return result.getModifiedSession() != null ? result.getModifiedSession().getName() : "";
            case 7:
                return result.getOriginalStatusCode();
            case 8:
                return result.getModifiedStatusCode();
            case 9:
                if (result.isVulnerable()) {
                    return "可能存在漏洞";
                } else if (result.isNeedsConfirmation()) {
                    return "需要确认";
                } else {
                    return "安全";
                }
            default:
                return "";
        }
    }

    @Override
    public void setValueAt(Object value, int row, int column) {
        if (column == 0 && value instanceof Boolean) {
            PrivilegeEscalationResult result = privilegeEscalationResults.get(row);
            result.setSelected((Boolean) value);
            fireTableCellUpdated(row, column);
            log.info("设置测试结果 " + result.getId() + " 的选中状态为: " + value);
        }
    }
}