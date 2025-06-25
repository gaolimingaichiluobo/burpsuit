package burp;

import burp.Engine.VulnerabilityDetectionEngine;
import burp.export.ExportResult;
import burp.http.HttpServiceUtil;
import burp.model.*;
import burp.result.AuthTestResult;
import burp.result.CsrfTestResult;
import burp.result.PrivilegeEscalationResult;
import burp.result.UnsafeMethodTestResult;
import burp.session.TestSession;
import burp.utils.FileUtils;
import burp.utils.KeyWordUtils;
import burp.utils.MultipartFixer;
import burp.utils.UrlUtil;
import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import lombok.extern.slf4j.Slf4j;

import javax.swing.*;
import javax.swing.Timer;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

/**
 * Burp Suite扩展主类
 * 整合HTTP请求导出、未授权访问测试和CSRF测试功能
 */
@Slf4j
public class BurpExtender implements IBurpExtender, ITab, IHttpListener, IContextMenuFactory {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private JPanel mainPanel;
    private JTabbedPane tabbedPane;
    private JPanel requestPanel;
    private JPanel authTestPanel;
    private JPanel csrfTestPanel;
    private JPanel unsafeMethodTestPanel;
    private JPanel privilegeEscalationPanel; // 新增越权测试面板
    private JButton exportButton;
    private JButton importButton; // 导入按钮
    private JTextField ipTextField; // IP输入框
    private JTextField portTextField; // 端口输入框
    private JButton testAuthButton;
    private JButton testCsrfButton;
    private JButton testUnsafeMethodButton;
    private JTextField excludeExtensionsField;
    private JTextField excludeUrlKeywordsField;
    private JCheckBox enableUrlDeduplicationCheckBox; // URL去重开关
    private JTable requestsTable;
    private JTable authTestResultsTable;
    private JTable csrfTestResultsTable;
    private JTable unsafeMethodResultsTable;
    private RequestTableModel tableModel;
    private AuthTestTableModel authTestTableModel;
    private CsrfTestTableModel csrfTestTableModel;
    private UnsafeMethodTestTableModel unsafeMethodTestTableModel;
    private PrivilegeEscalationTableModel privilegeEscalationTableModel; // 新增越权测试表格模型
    private List<RequestResponseInfo> capturedData;
    private List<AuthTestResult> authTestResults;
    private List<CsrfTestResult> csrfTestResults;
    private List<UnsafeMethodTestResult> unsafeMethodTestResults;
    private List<PrivilegeEscalationResult> privilegeEscalationResults; // 新增越权测试结果列表
    private JSplitPane authTestDetailSplitPane;
    private JSplitPane csrfTestDetailSplitPane;
    private JSplitPane unsafeMethodTestDetailSplitPane;
    private JTextArea requestViewer;
    private JTextArea responseViewer;
    private JTextArea csrfRequestViewer;
    private JTextArea csrfResponseViewer;
    private JTextArea unsafeMethodRequestViewer;
    private JTextArea unsafeMethodResponseViewer;
    private JTextArea privilegeEscalationOriginalRequestViewer; // 新增越权测试原始请求查看器
    private JTextArea privilegeEscalationOriginalResponseViewer; // 新增越权测试原始响应查看器
    private JTextArea privilegeEscalationModifiedRequestViewer; // 新增越权测试修改后请求查看器
    private JTextArea privilegeEscalationModifiedResponseViewer; // 新增越权测试修改后响应查看器
    private JTabbedPane authResponseTabbedPane;
    private JTabbedPane csrfResponseTabbedPane;
    private JTabbedPane unsafeMethodResponseTabbedPane;
    private JProgressBar progressBar;
    private JLabel statusLabel;
    // 在BurpExtender类中初始化引擎
    private VulnerabilityDetectionEngine vulnEngine;
    private HttpServiceUtil httpServiceUtil;
    // URL过滤和去重相关
    private List<String> safeKeywords = new ArrayList<>();
    private List<String> authSafeKeywords = new ArrayList<>();  // 未授权测试安全关键词
    private List<String> csrfSafeKeywords = new ArrayList<>();  // CSRF测试安全关键词
    private List<String> methodSafeKeywords = new ArrayList<>(); // 不安全HTTP方法测试安全关键词
    private Map<String, String> urlFilterCache = new HashMap<>();
    private Set<String> uniqueUrls = new HashSet<>();

    /**
     * Burp扩展的入口点，用于注册扩展功能和初始化
     *
     * @param callbacks Burp提供的回调接口，用于与Burp交互
     */
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {


        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.capturedData = new ArrayList<>();
        this.authTestResults = new ArrayList<>();
        this.csrfTestResults = new ArrayList<>();
        this.unsafeMethodTestResults = new ArrayList<>();
        this.privilegeEscalationResults = new ArrayList<>();

        // 初始化URL去重相关变量
        this.uniqueUrls = new HashSet<>();
        this.urlFilterCache = new HashMap<>();
        this.safeKeywords = new ArrayList<>();
        this.authSafeKeywords = new ArrayList<>();
        this.csrfSafeKeywords = new ArrayList<>();
        this.methodSafeKeywords = new ArrayList<>();

        this.vulnEngine = new VulnerabilityDetectionEngine(helpers, safeKeywords, authSafeKeywords, csrfSafeKeywords, methodSafeKeywords);
        this.httpServiceUtil = new HttpServiceUtil(helpers);
        callbacks.setExtensionName("安全手工测试辅助工具");
        callbacks.registerHttpListener(this);

        // 注册右键菜单工厂
        callbacks.registerContextMenuFactory(this);

        log.info("安全手工测试辅助工具已加载");

        // 创建UI界面
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                mainPanel = new JPanel();
                mainPanel.setLayout(new BorderLayout());
                // 创建选项卡面板
                tabbedPane = new JTabbedPane();
                // 创建原始请求面板
                requestPanel = new JPanel(new BorderLayout());
                // 创建未授权测试结果面板
                authTestPanel = new JPanel(new BorderLayout());
                // 创建CSRF测试结果面板
                csrfTestPanel = new JPanel(new BorderLayout());
                // 创建不安全HTTP方法测试结果面板
                unsafeMethodTestPanel = new JPanel(new BorderLayout());
                // 创建上部控制面板
                JPanel controlPanel = new JPanel();
                controlPanel.setLayout(new GridBagLayout());
                GridBagConstraints gbc = new GridBagConstraints();
                gbc.gridx = 0;
                gbc.gridy = 0;
                gbc.anchor = GridBagConstraints.WEST;
                gbc.insets = new Insets(5, 5, 5, 5);

                // 第一行：导出/导入类型和按钮
                exportButton = new JButton("导出选中数据");
                exportButton.addActionListener(e -> exportData());

                // 添加导出sqlmap格式按钮
                JButton exportSqlmapButton = new JButton("导出sqlmap格式");
                exportSqlmapButton.addActionListener(e -> exportSqlmapFormat());

                // 添加导入按钮
                importButton = new JButton("导入数据");
                importButton.addActionListener(e -> importData());

                // IP和端口修改
                JLabel ipLabel = new JLabel("目标IP:");
                ipTextField = new JTextField("", 10);
                ipTextField.setPreferredSize(new Dimension(100, 25)); // 固定大小
                ipTextField.setMaximumSize(ipTextField.getPreferredSize());
                JLabel portLabel = new JLabel("端口:");
                portTextField = new JTextField("", 5);
                portTextField.setPreferredSize(new Dimension(60, 25)); // 固定大小
                portTextField.setMaximumSize(portTextField.getPreferredSize());

                // 添加测试未授权访问的按钮
                testAuthButton = new JButton("测试未授权访问");
                testAuthButton.addActionListener(e -> {
                    // 先清空现有的测试结果
                    clearAuthTestResults();
                    testUnauthorizedAccess();
                });

                // 添加测试CSRF的按钮
                testCsrfButton = new JButton("测试CSRF漏洞");
                testCsrfButton.addActionListener(e -> {
                    // 先清空现有的测试结果
                    clearCsrfTestResults();
                    testCsrfVulnerability();
                });

                // 添加测试不安全HTTP方法的按钮
                testUnsafeMethodButton = new JButton("测试不安全请求");
                testUnsafeMethodButton.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        // 先清空现有的测试结果
                        clearUnsafeMethodTestResults();
                        testUnsafeHttpMethods();
                    }
                });

                // 添加测试越权的按钮
                JButton testPrivilegeEscalationButton = new JButton("测试越权");
                testPrivilegeEscalationButton.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        // 切换到越权测试标签页
                        tabbedPane.setSelectedComponent(privilegeEscalationPanel);

                        // 显示提示信息
                        JOptionPane.showMessageDialog(mainPanel, "请求已成功添加到越权测试模块。\n请在越权测试模块中配置会话和测试参数，然后点击开始测试。", "信息", JOptionPane.INFORMATION_MESSAGE);
                    }
                });

                // 创建第一行面板：导出、导入按钮和IP/端口输入框
                JPanel firstRowPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
                firstRowPanel.add(exportButton);
                firstRowPanel.add(exportSqlmapButton);
                firstRowPanel.add(importButton);

                // 创建IP和端口输入面板
                JPanel ipPortPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
                ipPortPanel.add(ipLabel);
                ipPortPanel.add(ipTextField);
                ipPortPanel.add(portLabel);
                ipPortPanel.add(portTextField);

                // 将IP和端口输入面板添加到第一行
                firstRowPanel.add(ipPortPanel);

                // 添加第一行到控制面板
                gbc.gridx = 0;
                gbc.gridy = 0;
                gbc.gridwidth = GridBagConstraints.REMAINDER;
                gbc.fill = GridBagConstraints.HORIZONTAL;
                controlPanel.add(firstRowPanel, gbc);

                // 创建第二行面板：测试按钮，间距相等
                JPanel secondRowPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
                secondRowPanel.add(testAuthButton);
                secondRowPanel.add(testCsrfButton);
                secondRowPanel.add(testUnsafeMethodButton);
                secondRowPanel.add(testPrivilegeEscalationButton);

                // 添加第二行到控制面板
                gbc.gridy = 1;
                controlPanel.add(secondRowPanel, gbc);

                // 重置gridwidth和fill
                gbc.gridwidth = 1;
                gbc.fill = GridBagConstraints.NONE;

                // 第三行：URL去重开关
                gbc.gridx = 0;
                gbc.gridy = 2;
                gbc.weightx = 0;


                // 添加URL去重开关
                enableUrlDeduplicationCheckBox = new JCheckBox("开启URL去重", true);
                enableUrlDeduplicationCheckBox.setToolTipText("开启后将自动移除URL参数并对重复URL只保留一个");
                enableUrlDeduplicationCheckBox.addActionListener(e -> {
                    // 如果关闭去重，清空去重集合，便于重新开始收集
                    if (!enableUrlDeduplicationCheckBox.isSelected()) {
                        uniqueUrls.clear();
                        log.info("URL去重功能已关闭，已清空去重集合");
                    } else {
                        log.info("URL去重功能已开启");
                    }
                });

                JButton clearButton = new JButton("刪除已选中");
                clearButton.addActionListener(e -> clearData());

                // 新增：更新请求头按钮
                JButton updateHeaderButton = new JButton("更新请求头");
                updateHeaderButton.addActionListener(e -> {
                    // 弹出输入窗口
                    JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(mainPanel), "更新请求头", true);
                    dialog.setLayout(new BorderLayout());

                    JPanel inputPanel = new JPanel();
                    inputPanel.setLayout(new GridLayout(2, 2, 5, 5));
                    JLabel keyLabel = new JLabel("请求头Key:");
                    JTextField keyField = new JTextField(20);
                    JLabel valueLabel = new JLabel("请求头Value:");
                    JTextField valueField = new JTextField(20);
                    inputPanel.add(keyLabel);
                    inputPanel.add(keyField);
                    inputPanel.add(valueLabel);
                    inputPanel.add(valueField);

                    JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
                    JButton cancelButton = new JButton("取消");
                    JButton confirmButton = new JButton("确认");
                    buttonPanel.add(cancelButton);
                    buttonPanel.add(confirmButton);

                    cancelButton.addActionListener(ev -> dialog.dispose());
                    confirmButton.addActionListener(ev -> {
                        String key = keyField.getText().trim();
                        String value = valueField.getText().trim();
                        if (!key.isEmpty()) {
                            // 调用你自定义的替换方法
                            updateRequestHeadersForSelected(key, value);
                        }
                        dialog.dispose();
                    });

                    dialog.add(inputPanel, BorderLayout.CENTER);
                    dialog.add(buttonPanel, BorderLayout.SOUTH);
                    dialog.pack();
                    dialog.setLocationRelativeTo(mainPanel);
                    dialog.setVisible(true);
                });

                // 创建第三行面板：URL去重开关和清空列表按钮
                JPanel thirdRowPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
                thirdRowPanel.add(enableUrlDeduplicationCheckBox);
                thirdRowPanel.add(clearButton);
                thirdRowPanel.add(updateHeaderButton);

                // 添加第三行到控制面板
                gbc.gridx = 0;
                gbc.gridy = 2;
                gbc.gridwidth = GridBagConstraints.REMAINDER;
                controlPanel.add(thirdRowPanel, gbc);

                // 重置gridwidth
                gbc.gridwidth = 1;

                // 第四行：排除后缀
                gbc.gridx = 0;
                gbc.gridy = 3;
                gbc.weightx = 0;
                JLabel excludeLabel = new JLabel("排除后缀(用逗号分隔):");
                excludeExtensionsField = new JTextField("css,js,png,jpg,jpeg,gif,webp,svg,ico,woff,woff2,ttf,eot,mp3,mp4,wav,ogg,avi,mov,wmv,flv,pdf,doc,docx,xls,xlsx,ppt,pptx,zip,rar,gz,bmp,tif,tiff,swf,map", 30);
                JButton applyExcludeButton = new JButton("应用过滤");
                applyExcludeButton.addActionListener(e -> applyExcludeFilter());

                // 创建第四行面板：排除后缀
                JPanel fourthRowPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
                fourthRowPanel.add(excludeLabel);

                // 设置文本框宽度
                excludeExtensionsField.setPreferredSize(new Dimension(500, 25));
                fourthRowPanel.add(excludeExtensionsField);
                fourthRowPanel.add(applyExcludeButton);

                // 添加第四行到控制面板
                gbc.gridx = 0;
                gbc.gridwidth = GridBagConstraints.REMAINDER;
                gbc.fill = GridBagConstraints.HORIZONTAL;
                controlPanel.add(fourthRowPanel, gbc);

                // 第五行：排除URL关键词
                gbc.gridx = 0;
                gbc.gridy = 4;
                gbc.gridwidth = 1;
                gbc.weightx = 0;
                gbc.fill = GridBagConstraints.NONE;
                JLabel excludeUrlLabel = new JLabel("排除URL关键词(用逗号分隔):");
                excludeUrlKeywordsField = new JTextField("check_", 30);
                JButton applyUrlExcludeButton = new JButton("应用过滤");
                applyUrlExcludeButton.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        applyExcludeFilter();
                    }
                });

                // 创建第五行面板：排除URL关键词
                JPanel fifthRowPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
                fifthRowPanel.add(excludeUrlLabel);

                // 设置文本框宽度
                excludeUrlKeywordsField.setPreferredSize(new Dimension(500, 25));
                fifthRowPanel.add(excludeUrlKeywordsField);
                fifthRowPanel.add(applyUrlExcludeButton);

                // 添加第五行到控制面板
                gbc.gridx = 0;
                gbc.gridwidth = GridBagConstraints.REMAINDER;
                gbc.fill = GridBagConstraints.HORIZONTAL;
                controlPanel.add(fifthRowPanel, gbc);

                // 重置fill和gridwidth
                gbc.fill = GridBagConstraints.NONE;
                gbc.gridwidth = 1;

                // 创建表格模型
                tableModel = new RequestTableModel(capturedData);
                requestsTable = new JTable(tableModel);
                requestsTable.setAutoCreateRowSorter(true);

                // 设置表格列宽
                requestsTable.getColumnModel().getColumn(0).setMaxWidth(50); // 选择列
                requestsTable.getColumnModel().getColumn(1).setMaxWidth(50); // 序号列

                // 添加表格排序器
                TableRowSorter<RequestTableModel> sorter = new TableRowSorter<>(tableModel);
                requestsTable.setRowSorter(sorter);

                //todo 如果想添加请求列表的请求查看器可以在这里添加

                // 设置状态码列的渲染器，根据状态码显示不同颜色
                requestsTable.getColumnModel().getColumn(4).setCellRenderer(new DefaultTableCellRenderer() {
                    @Override
                    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                        Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

                        if (!isSelected) {
                            int statusCode = (Integer) value;
                            if (statusCode >= 200 && statusCode < 300) {
                                c.setForeground(new Color(0, 128, 0)); // 绿色表示成功
                            } else if (statusCode >= 300 && statusCode < 400) {
                                c.setForeground(new Color(255, 140, 0)); // 橙色表示重定向
                            } else if (statusCode >= 400 && statusCode < 500) {
                                c.setForeground(new Color(255, 0, 0)); // 红色表示客户端错误
                            } else if (statusCode >= 500) {
                                c.setForeground(new Color(128, 0, 128)); // 紫色表示服务器错误
                            } else {
                                c.setForeground(table.getForeground()); // 默认颜色
                            }
                        }

                        return c;
                    }
                });

                // 添加全选/取消全选按钮
                JPanel selectionPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
                JButton selectAllButton = new JButton("全选");
                selectAllButton.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        for (RequestResponseInfo info : capturedData) {
                            info.setSelected(true);
                        }
                        tableModel.fireTableDataChanged();
                        log.info("已全选 " + capturedData.size() + " 条记录");
                    }
                });

                JButton deselectAllButton = new JButton("取消全选");
                deselectAllButton.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        for (RequestResponseInfo info : capturedData) {
                            info.setSelected(false);
                        }
                        tableModel.fireTableDataChanged();
                        log.info("已取消全选 {} 条记录", capturedData.size());
                    }
                });

                selectionPanel.add(selectAllButton);
                selectionPanel.add(deselectAllButton);

                // 添加表格到面板
                JScrollPane tableScrollPane = new JScrollPane(requestsTable);

                // 将控制面板和表格添加到请求面板
                requestPanel.add(controlPanel, BorderLayout.NORTH);
                requestPanel.add(selectionPanel, BorderLayout.SOUTH);
                requestPanel.add(tableScrollPane, BorderLayout.CENTER);

                // 添加双击事件，显示请求和响应详情
                requestsTable.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e) {
                        if (e.getClickCount() == 2) {
                            int row = requestsTable.getSelectedRow();
                            if (row >= 0 && row < capturedData.size()) {
                                int modelRow = requestsTable.convertRowIndexToModel(row);
                                RequestResponseInfo info = capturedData.get(modelRow);

                                // 创建弹窗
                                JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(mainPanel), "请求与响应详情", true);
                                dialog.setLayout(new BorderLayout());

                                JTextArea requestArea = new JTextArea(info.getRequestHeaders() + info.getRequestBody());
                                requestArea.setEditable(false);
                                JTextArea responseArea = new JTextArea(info.getResponseBody());
                                responseArea.setEditable(false);

                                JTabbedPane tabbedPane = new JTabbedPane();
                                tabbedPane.addTab("请求", new JScrollPane(requestArea));
                                tabbedPane.addTab("响应", new JScrollPane(responseArea));

                                dialog.add(tabbedPane, BorderLayout.CENTER);

                                JButton closeButton = new JButton("关闭");
                                closeButton.addActionListener(ev -> dialog.dispose());
                                JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
                                buttonPanel.add(closeButton);

                                dialog.add(buttonPanel, BorderLayout.SOUTH);
                                dialog.setSize(800, 600);
                                dialog.setLocationRelativeTo(mainPanel);
                                dialog.setVisible(true);
                            }
                        }
                    }
                });

                // 创建未授权测试结果表格模型
                authTestTableModel = new AuthTestTableModel(authTestResults);
                authTestResultsTable = new JTable(authTestTableModel);

                // 设置表格列宽
                authTestResultsTable.getColumnModel().getColumn(0).setMaxWidth(50); // 选择列
                authTestResultsTable.getColumnModel().getColumn(1).setMaxWidth(50); // 序号列

                // 添加表格排序器
                TableRowSorter<AuthTestTableModel> authSorter = new TableRowSorter<>(authTestTableModel);
                authTestResultsTable.setRowSorter(authSorter);

                // 设置状态码列的渲染器
                authTestResultsTable.getColumnModel().getColumn(3).setCellRenderer(new DefaultTableCellRenderer() {
                    @Override
                    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                        Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

                        if (!isSelected) {
                            int statusCode = (Integer) value;
                            if (statusCode >= 200 && statusCode < 300) {
                                c.setForeground(new Color(0, 128, 0)); // 绿色表示成功
                            } else if (statusCode >= 300 && statusCode < 400) {
                                c.setForeground(new Color(255, 140, 0)); // 橙色表示重定向
                            } else if (statusCode >= 400 && statusCode < 500) {
                                c.setForeground(new Color(255, 0, 0)); // 红色表示客户端错误
                            } else if (statusCode >= 500) {
                                c.setForeground(new Color(128, 0, 128)); // 紫色表示服务器错误
                            } else {
                                c.setForeground(table.getForeground()); // 默认颜色
                            }
                        }

                        return c;
                    }
                });

                // 设置测试结果列的渲染器
                authTestResultsTable.getColumnModel().getColumn(4).setCellRenderer(new DefaultTableCellRenderer() {
                    @Override
                    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                        Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

                        if (!isSelected) {
                            String result = (String) value;
                            if (result.contains("存在漏洞")) {
                                c.setForeground(new Color(255, 0, 0)); // 红色表示漏洞
                            } else if (result.contains("需要确认")) {
                                c.setForeground(new Color(255, 140, 0)); // 橙色表示需要确认
                            } else {
                                c.setForeground(new Color(0, 128, 0)); // 绿色表示安全
                            }
                        }

                        return c;
                    }
                });

                // 添加整行颜色渲染的表格渲染器
                authTestResultsTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
                    @Override
                    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                        Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

                        if (!isSelected) {
                            int modelRow = table.convertRowIndexToModel(row);
                            if (modelRow < authTestResults.size()) {
                                AuthTestResult result = authTestResults.get(modelRow);
                                if (result.isVulnerable()) {
                                    c.setBackground(new Color(255, 200, 200)); // 浅红色背景表示漏洞
                                } else if (result.isNeedsConfirmation()) {
                                    c.setBackground(new Color(255, 235, 200)); // 浅橙色背景表示需要确认
                                } else {
                                    c.setBackground(new Color(220, 255, 220)); // 浅绿色背景表示安全
                                }
                            } else {
                                c.setBackground(table.getBackground());
                            }
                        }

                        return c;
                    }
                });

                // 添加双击事件，显示请求和响应详情
                authTestResultsTable.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e) {
                        if (e.getClickCount() == 2) {
                            int row = authTestResultsTable.convertRowIndexToModel(authTestResultsTable.getSelectedRow());
                            if (row >= 0 && row < authTestResults.size()) {
                                AuthTestResult result = authTestResults.get(row);
                                requestViewer.setText(result.getRequestHeaders() + result.getRequestBody());
                                responseViewer.setText(result.getResponseHeaders() + result.getResponseBody());
                            }
                        }
                    }
                });

                // 添加未授权测试结果控制面板
                JPanel authControlPanel = new JPanel();
                authControlPanel.setLayout(new BoxLayout(authControlPanel, BoxLayout.Y_AXIS));

                // 上部按钮面板
                JPanel authButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

                JButton clearAuthResultsButton = new JButton("清空结果");
                clearAuthResultsButton.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        clearAuthTestResults();
                    }
                });

                JButton exportAuthResultsButton = new JButton("导出结果");
                exportAuthResultsButton.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        exportAuthTestResults();
                    }
                });

                JButton confirmVulnButton = new JButton("确认漏洞");
                confirmVulnButton.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        confirmAuthTestResult();
                    }
                });

                JButton batchConfirmButton = new JButton("批量确认");
                batchConfirmButton.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        batchConfirmAuthTestResults();
                    }
                });

                // 添加全选/取消全选按钮
                JButton selectAllAuthButton = new JButton("全选");
                selectAllAuthButton.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        for (AuthTestResult result : authTestResults) {
                            result.setSelected(true);
                        }
                        authTestTableModel.fireTableDataChanged();
                        log.info("已全选 " + authTestResults.size() + " 条测试结果");
                    }
                });

                JButton deselectAllAuthButton = new JButton("取消全选");
                deselectAllAuthButton.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        for (AuthTestResult result : authTestResults) {
                            result.setSelected(false);
                        }
                        authTestTableModel.fireTableDataChanged();
                        log.info("已取消全选 " + authTestResults.size() + " 条测试结果");
                    }
                });

                authButtonPanel.add(clearAuthResultsButton);
                authButtonPanel.add(exportAuthResultsButton);
                authButtonPanel.add(confirmVulnButton);
                authButtonPanel.add(batchConfirmButton);
                authButtonPanel.add(selectAllAuthButton);
                authButtonPanel.add(deselectAllAuthButton);

                // 添加重新测试按钮
                JButton retestAuthButton = new JButton("重新测试");
                retestAuthButton.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        testUnauthorizedAccess();
                    }
                });
                authButtonPanel.add(retestAuthButton);

                // 下部关键词面板
                JPanel authKeywordPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
                JLabel authSafeKeywordsLabel = new JLabel("安全关键词:");
                JTextField authSafeKeywordsField = new JTextField("", 30);
                JLabel authSafeKeywordsHint = new JLabel("多个关键词用逗号分隔，响应中含有关键词则判定为安全");

                authKeywordPanel.add(authSafeKeywordsLabel);
                authKeywordPanel.add(authSafeKeywordsField);
                authKeywordPanel.add(authSafeKeywordsHint);

                // 添加键盘监听器，在测试前保存关键词
                authSafeKeywordsField.addKeyListener(new KeyAdapter() {
                    @Override
                    public void keyReleased(KeyEvent e) {
                        // 更新安全关键词列表
                        authSafeKeywords.clear();
                        String keywordsText = authSafeKeywordsField.getText().trim();
                        if (!keywordsText.isEmpty()) {
                            for (String keyword : keywordsText.split(",")) {
                                authSafeKeywords.add(keyword.trim().toLowerCase());
                            }
                        }
                    }
                });

                // 将两个面板添加到主控制面板
                authControlPanel.add(authButtonPanel);
                authControlPanel.add(authKeywordPanel);

                // 创建请求和响应查看器
                requestViewer = new JTextArea();
                requestViewer.setEditable(false);
                responseViewer = new JTextArea();
                responseViewer.setEditable(false);

                JScrollPane requestScrollPane = new JScrollPane(requestViewer);
                JScrollPane responseScrollPane = new JScrollPane(responseViewer);

                // 创建响应标签页面板
                authResponseTabbedPane = new JTabbedPane();
                authResponseTabbedPane.addTab("原始响应", responseScrollPane);

                // 创建分割面板 - 改为左右模式
                authTestDetailSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestScrollPane, authResponseTabbedPane);
                authTestDetailSplitPane.setResizeWeight(0.5);

                // 创建主分割面板
                JSplitPane authTestSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(authTestResultsTable), authTestDetailSplitPane);
                authTestSplitPane.setResizeWeight(0.5);

                // 将控制面板和分割面板添加到未授权测试面板
                authTestPanel.add(authControlPanel, BorderLayout.NORTH);
                authTestPanel.add(authTestSplitPane, BorderLayout.CENTER);

                // 将面板添加到选项卡
                tabbedPane.addTab("请求列表", requestPanel);
                tabbedPane.addTab("未授权测试结果", authTestPanel);

                // 创建CSRF测试结果表格模型
                csrfTestTableModel = new CsrfTestTableModel(csrfTestResults);
                csrfTestResultsTable = new JTable(csrfTestTableModel);

                // 设置表格列宽
                csrfTestResultsTable.getColumnModel().getColumn(0).setMaxWidth(50); // 选择列
                csrfTestResultsTable.getColumnModel().getColumn(1).setMaxWidth(50); // 序号列

                // 添加表格排序器
                TableRowSorter<CsrfTestTableModel> csrfSorter = new TableRowSorter<>(csrfTestTableModel);
                csrfTestResultsTable.setRowSorter(csrfSorter);

                // 设置状态码列的渲染器
                csrfTestResultsTable.getColumnModel().getColumn(3).setCellRenderer(new DefaultTableCellRenderer() {
                    @Override
                    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                        Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

                        if (!isSelected) {
                            int statusCode = (Integer) value;
                            if (statusCode >= 200 && statusCode < 300) {
                                c.setForeground(new Color(0, 128, 0)); // 绿色表示成功
                            } else if (statusCode >= 300 && statusCode < 400) {
                                c.setForeground(new Color(255, 140, 0)); // 橙色表示重定向
                            } else if (statusCode >= 400 && statusCode < 500) {
                                c.setForeground(new Color(255, 0, 0)); // 红色表示客户端错误
                            } else if (statusCode >= 500) {
                                c.setForeground(new Color(128, 0, 128)); // 紫色表示服务器错误
                            } else {
                                c.setForeground(table.getForeground()); // 默认颜色
                            }
                        }

                        return c;
                    }
                });

                // 设置测试结果列的渲染器
                csrfTestResultsTable.getColumnModel().getColumn(4).setCellRenderer(new DefaultTableCellRenderer() {
                    @Override
                    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                        Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

                        if (!isSelected) {
                            String result = (String) value;
                            if (result.contains("存在CSRF漏洞")) {
                                c.setForeground(new Color(255, 0, 0)); // 红色表示漏洞
                            } else if (result.contains("需要确认")) {
                                c.setForeground(new Color(255, 140, 0)); // 橙色表示需要确认
                            } else {
                                c.setForeground(new Color(0, 128, 0)); // 绿色表示安全
                            }
                        }

                        return c;
                    }
                });

                // 添加整行颜色渲染的表格渲染器
                csrfTestResultsTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
                    @Override
                    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                        Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

                        if (!isSelected) {
                            int modelRow = table.convertRowIndexToModel(row);
                            if (modelRow < csrfTestResults.size()) {
                                CsrfTestResult result = csrfTestResults.get(modelRow);
                                if (result.isVulnerable()) {
                                    c.setBackground(new Color(255, 200, 200)); // 浅红色背景表示漏洞
                                } else if (result.isNeedsConfirmation()) {
                                    c.setBackground(new Color(255, 235, 200)); // 浅橙色背景表示需要确认
                                } else {
                                    c.setBackground(new Color(220, 255, 220)); // 浅绿色背景表示安全
                                }
                            } else {
                                c.setBackground(table.getBackground());
                            }
                        }

                        return c;
                    }
                });

                // 添加双击事件，显示请求和响应详情
                csrfTestResultsTable.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e) {
                        if (e.getClickCount() == 2) {
                            int row = csrfTestResultsTable.convertRowIndexToModel(csrfTestResultsTable.getSelectedRow());
                            if (row >= 0 && row < csrfTestResults.size()) {
                                CsrfTestResult result = csrfTestResults.get(row);
                                csrfRequestViewer.setText(result.getRequestHeaders() + result.getRequestBody());
                                csrfResponseViewer.setText(result.getResponseHeaders() + result.getResponseBody());
                            }
                        }
                    }
                });

                // 添加CSRF测试结果控制面板
                JPanel csrfControlPanel = new JPanel();
                csrfControlPanel.setLayout(new BoxLayout(csrfControlPanel, BoxLayout.Y_AXIS));

                // 上部按钮面板
                JPanel csrfButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

                JButton clearCsrfResultsButton = new JButton("清空结果");
                clearCsrfResultsButton.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        clearCsrfTestResults();
                    }
                });

                JButton exportCsrfResultsButton = new JButton("导出结果");
                exportCsrfResultsButton.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        exportCsrfTestResults();
                    }
                });

                JButton confirmCsrfVulnButton = new JButton("确认漏洞");
                confirmCsrfVulnButton.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        confirmCsrfTestResult();
                    }
                });

                JButton batchConfirmCsrfButton = new JButton("批量确认");
                batchConfirmCsrfButton.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        batchConfirmCsrfTestResults();
                    }
                });

                // 添加全选/取消全选按钮
                JButton selectAllCsrfButton = new JButton("全选");
                selectAllCsrfButton.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        for (CsrfTestResult result : csrfTestResults) {
                            result.setSelected(true);
                        }
                        csrfTestTableModel.fireTableDataChanged();
                        log.info("已全选 " + csrfTestResults.size() + " 条CSRF测试结果");
                    }
                });

                JButton deselectAllCsrfButton = new JButton("取消全选");
                deselectAllCsrfButton.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        for (CsrfTestResult result : csrfTestResults) {
                            result.setSelected(false);
                        }
                        csrfTestTableModel.fireTableDataChanged();
                        log.info("已取消全选 " + csrfTestResults.size() + " 条CSRF测试结果");
                    }
                });

                csrfButtonPanel.add(clearCsrfResultsButton);
                csrfButtonPanel.add(exportCsrfResultsButton);
                csrfButtonPanel.add(confirmCsrfVulnButton);
                csrfButtonPanel.add(batchConfirmCsrfButton);
                csrfButtonPanel.add(selectAllCsrfButton);
                csrfButtonPanel.add(deselectAllCsrfButton);

                // 添加重新测试按钮
                JButton retestCsrfButton = new JButton("重新测试");
                retestCsrfButton.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        testCsrfVulnerability();
                    }
                });
                csrfButtonPanel.add(retestCsrfButton);

                // 下部关键词面板
                JPanel csrfKeywordPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
                JLabel csrfSafeKeywordsLabel = new JLabel("安全关键词:");
                JTextField csrfSafeKeywordsField = new JTextField("", 30);
                JLabel csrfSafeKeywordsHint = new JLabel("多个关键词用逗号分隔，响应中含有关键词则判定为安全");

                csrfKeywordPanel.add(csrfSafeKeywordsLabel);
                csrfKeywordPanel.add(csrfSafeKeywordsField);
                csrfKeywordPanel.add(csrfSafeKeywordsHint);

                // 添加键盘监听器，在测试前保存关键词
                csrfSafeKeywordsField.addKeyListener(new KeyAdapter() {
                    @Override
                    public void keyReleased(KeyEvent e) {
                        // 更新安全关键词列表
                        csrfSafeKeywords.clear();
                        String keywordsText = csrfSafeKeywordsField.getText().trim();
                        if (!keywordsText.isEmpty()) {
                            for (String keyword : keywordsText.split(",")) {
                                csrfSafeKeywords.add(keyword.trim().toLowerCase());
                            }
                        }
                    }
                });

                // 将两个面板添加到主控制面板
                csrfControlPanel.add(csrfButtonPanel);
                csrfControlPanel.add(csrfKeywordPanel);

                // 创建请求和响应查看器
                csrfRequestViewer = new JTextArea();
                csrfRequestViewer.setEditable(false);
                csrfResponseViewer = new JTextArea();
                csrfResponseViewer.setEditable(false);

                JScrollPane csrfRequestScrollPane = new JScrollPane(csrfRequestViewer);
                JScrollPane csrfResponseScrollPane = new JScrollPane(csrfResponseViewer);


                // 创建响应标签页面板
                csrfResponseTabbedPane = new JTabbedPane();
                csrfResponseTabbedPane.addTab("原始响应", csrfResponseScrollPane);

                // 创建分割面板 - 改为左右模式
                csrfTestDetailSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, csrfRequestScrollPane, csrfResponseTabbedPane);
                csrfTestDetailSplitPane.setResizeWeight(0.5);

                // 创建主分割面板
                JSplitPane csrfTestSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(csrfTestResultsTable), csrfTestDetailSplitPane);
                csrfTestSplitPane.setResizeWeight(0.5);

                // 将控制面板和分割面板添加到CSRF测试面板
                csrfTestPanel.add(csrfControlPanel, BorderLayout.NORTH);
                csrfTestPanel.add(csrfTestSplitPane, BorderLayout.CENTER);

                // 将面板添加到选项卡
                tabbedPane.addTab("CSRF测试结果", csrfTestPanel);

                // 创建不安全HTTP方法测试表格模型
                unsafeMethodTestTableModel = new UnsafeMethodTestTableModel(unsafeMethodTestResults);
                unsafeMethodResultsTable = new JTable(unsafeMethodTestTableModel);

                // 设置表格列宽
                unsafeMethodResultsTable.getColumnModel().getColumn(0).setMaxWidth(50); // 选择列
                unsafeMethodResultsTable.getColumnModel().getColumn(1).setMaxWidth(50); // 序号列

                // 添加表格排序器
                TableRowSorter<UnsafeMethodTestTableModel> unsafeMethodSorter = new TableRowSorter<>(unsafeMethodTestTableModel);
                unsafeMethodResultsTable.setRowSorter(unsafeMethodSorter);

                // 设置状态码列的渲染器
                unsafeMethodResultsTable.getColumnModel().getColumn(4).setCellRenderer(new DefaultTableCellRenderer() {
                    @Override
                    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                        Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

                        if (!isSelected) {
                            int statusCode;
                            if (value instanceof Integer) {
                                statusCode = (Integer) value;
                            } else if (value instanceof String) {
                                try {
                                    statusCode = Integer.parseInt((String) value);
                                } catch (NumberFormatException e) {
                                    return c; // 返回默认渲染
                                }
                            } else {
                                return c; // 无法处理的类型，返回默认渲染
                            }

                            if (statusCode == 0) {
                                c.setForeground(new Color(0, 128, 0)); // 绿色表示安全
                            } else if (statusCode >= 200 && statusCode < 300) {
                                c.setForeground(new Color(0, 128, 0)); // 绿色表示成功
                            } else if (statusCode >= 300 && statusCode < 400) {
                                c.setForeground(new Color(255, 140, 0)); // 橙色表示重定向
                            } else if (statusCode >= 400 && statusCode < 500) {
                                c.setForeground(new Color(255, 0, 0)); // 红色表示客户端错误
                            } else if (statusCode >= 500) {
                                c.setForeground(new Color(128, 0, 128)); // 紫色表示服务器错误
                            } else {
                                c.setForeground(table.getForeground()); // 默认颜色
                            }
                        }

                        return c;
                    }
                });

                // 设置测试结果列的渲染器
                unsafeMethodResultsTable.getColumnModel().getColumn(5).setCellRenderer(new DefaultTableCellRenderer() {
                    @Override
                    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                        Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

                        if (!isSelected) {
                            String result = (String) value;
                            if (result.contains("存在漏洞")) {
                                c.setForeground(new Color(255, 0, 0)); // 红色表示漏洞
                            } else if (result.contains("需要确认")) {
                                c.setForeground(new Color(255, 140, 0)); // 橙色表示需要确认
                            } else {
                                c.setForeground(new Color(0, 128, 0)); // 绿色表示安全
                            }
                        }

                        return c;
                    }
                });

                // 添加整行颜色渲染的表格渲染器
                unsafeMethodResultsTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
                    @Override
                    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                        Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

                        if (!isSelected) {
                            int modelRow = table.convertRowIndexToModel(row);
                            if (modelRow < unsafeMethodTestResults.size()) {
                                UnsafeMethodTestResult result = unsafeMethodTestResults.get(modelRow);
                                if (result.isVulnerable()) {
                                    c.setBackground(new Color(255, 200, 200)); // 浅红色背景表示漏洞
                                } else if (result.isNeedsConfirmation()) {
                                    c.setBackground(new Color(255, 235, 200)); // 浅橙色背景表示需要确认
                                } else {
                                    c.setBackground(new Color(220, 255, 220)); // 浅绿色背景表示安全
                                }
                            } else {
                                c.setBackground(table.getBackground());
                            }
                        }

                        return c;
                    }
                });

                // 添加双击事件，显示请求和响应详情
                unsafeMethodResultsTable.addMouseListener(new MouseAdapter() {
                    @Override
                    public void mouseClicked(MouseEvent e) {
                        if (e.getClickCount() == 2) {
                            int row = unsafeMethodResultsTable.convertRowIndexToModel(unsafeMethodResultsTable.getSelectedRow());
                            if (row >= 0 && row < unsafeMethodTestResults.size()) {
                                UnsafeMethodTestResult result = unsafeMethodTestResults.get(row);
                                unsafeMethodRequestViewer.setText(result.getRequestHeaders() + result.getRequestBody());
                                unsafeMethodResponseViewer.setText(result.getResponseHeaders() + result.getResponseBody());
                            }
                        }
                    }
                });

                // 添加不安全HTTP方法测试控制面板
                JPanel unsafeMethodControlPanel = new JPanel();
                unsafeMethodControlPanel.setLayout(new BoxLayout(unsafeMethodControlPanel, BoxLayout.Y_AXIS));

                // 上部按钮面板
                JPanel unsafeMethodButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

                JButton clearUnsafeMethodResultsButton = new JButton("清空结果");
                clearUnsafeMethodResultsButton.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        clearUnsafeMethodTestResults();
                    }
                });

                JButton exportUnsafeMethodResultsButton = new JButton("导出结果");
                exportUnsafeMethodResultsButton.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        exportUnsafeMethodTestResults();
                    }
                });

                JButton confirmUnsafeMethodVulnButton = new JButton("确认漏洞");
                confirmUnsafeMethodVulnButton.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        confirmUnsafeMethodTestResult();
                    }
                });

                JButton batchConfirmUnsafeMethodButton = new JButton("批量确认");
                batchConfirmUnsafeMethodButton.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        batchConfirmUnsafeMethodTestResults();
                    }
                });

                // 添加全选/取消全选按钮
                JButton selectAllUnsafeMethodButton = new JButton("全选");
                selectAllUnsafeMethodButton.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        for (UnsafeMethodTestResult result : unsafeMethodTestResults) {
                            result.setSelected(true);
                        }
                        unsafeMethodTestTableModel.fireTableDataChanged();
                        log.info("已全选 " + unsafeMethodTestResults.size() + " 条不安全HTTP方法测试结果");
                    }
                });

                JButton deselectAllUnsafeMethodButton = new JButton("取消全选");
                deselectAllUnsafeMethodButton.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        for (UnsafeMethodTestResult result : unsafeMethodTestResults) {
                            result.setSelected(false);
                        }
                        unsafeMethodTestTableModel.fireTableDataChanged();
                        log.info("已取消全选 " + unsafeMethodTestResults.size() + " 条不安全HTTP方法测试结果");
                    }
                });

                unsafeMethodButtonPanel.add(clearUnsafeMethodResultsButton);
                unsafeMethodButtonPanel.add(exportUnsafeMethodResultsButton);
                unsafeMethodButtonPanel.add(confirmUnsafeMethodVulnButton);
                unsafeMethodButtonPanel.add(batchConfirmUnsafeMethodButton);
                unsafeMethodButtonPanel.add(selectAllUnsafeMethodButton);
                unsafeMethodButtonPanel.add(deselectAllUnsafeMethodButton);

                // 添加重新测试按钮
                JButton retestUnsafeMethodButton = new JButton("重新测试");
                retestUnsafeMethodButton.addActionListener(new ActionListener() {
                    @Override
                    public void actionPerformed(ActionEvent e) {
                        testUnsafeHttpMethods();
                    }
                });
                unsafeMethodButtonPanel.add(retestUnsafeMethodButton);

                // 下部关键词面板
                JPanel methodKeywordPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
                JLabel methodSafeKeywordsLabel = new JLabel("安全关键词:");
                JTextField methodSafeKeywordsField = new JTextField("", 30);
                JLabel methodSafeKeywordsHint = new JLabel("多个关键词用逗号分隔，响应中含有关键词则判定为安全");

                methodKeywordPanel.add(methodSafeKeywordsLabel);
                methodKeywordPanel.add(methodSafeKeywordsField);
                methodKeywordPanel.add(methodSafeKeywordsHint);

                // 添加键盘监听器，在测试前保存关键词
                methodSafeKeywordsField.addKeyListener(new KeyAdapter() {
                    @Override
                    public void keyReleased(KeyEvent e) {
                        // 更新安全关键词列表
                        methodSafeKeywords.clear();
                        String keywordsText = methodSafeKeywordsField.getText().trim();
                        if (!keywordsText.isEmpty()) {
                            for (String keyword : keywordsText.split(",")) {
                                methodSafeKeywords.add(keyword.trim().toLowerCase());
                            }
                        }
                    }
                });

                // 将两个面板添加到主控制面板
                unsafeMethodControlPanel.add(unsafeMethodButtonPanel);
                unsafeMethodControlPanel.add(methodKeywordPanel);

                // 创建请求和响应查看器
                unsafeMethodRequestViewer = new JTextArea();
                unsafeMethodRequestViewer.setEditable(false);
                unsafeMethodResponseViewer = new JTextArea();
                unsafeMethodResponseViewer.setEditable(false);

                JScrollPane unsafeMethodRequestScrollPane = new JScrollPane(unsafeMethodRequestViewer);
                JScrollPane unsafeMethodResponseScrollPane = new JScrollPane(unsafeMethodResponseViewer);


                // 创建响应标签页面板
                unsafeMethodResponseTabbedPane = new JTabbedPane();
                unsafeMethodResponseTabbedPane.addTab("原始响应", unsafeMethodResponseScrollPane);

                // 创建分割面板 - 改为左右模式
                unsafeMethodTestDetailSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, unsafeMethodRequestScrollPane, unsafeMethodResponseTabbedPane);
                unsafeMethodTestDetailSplitPane.setResizeWeight(0.5);

                // 创建主分割面板
                JSplitPane unsafeMethodTestSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(unsafeMethodResultsTable), unsafeMethodTestDetailSplitPane);
                unsafeMethodTestSplitPane.setResizeWeight(0.5);

                // 将控制面板和分割面板添加到不安全HTTP方法测试面板
                unsafeMethodTestPanel.add(unsafeMethodControlPanel, BorderLayout.NORTH);
                unsafeMethodTestPanel.add(unsafeMethodTestSplitPane, BorderLayout.CENTER);

                // 将面板添加到选项卡
                tabbedPane.addTab("不安全请求测试结果", unsafeMethodTestPanel);

                // 创建越权测试面板
                createPrivilegeEscalationTestPanel();

                // 将越权测试面板添加到选项卡
                tabbedPane.addTab("越权测试", privilegeEscalationPanel);

                // 将选项卡面板添加到主面板
                mainPanel.add(tabbedPane, BorderLayout.CENTER);

                // 设置URL去重开关的默认状态
                if (enableUrlDeduplicationCheckBox != null) {
                    enableUrlDeduplicationCheckBox.setSelected(true); // 确保默认开启
                    log.info("URL去重功能已默认开启");
                } else {
                    log.error("URL去重选项未正确初始化！");
                }

                // 添加底部状态栏和进度条
                JPanel statusPanel = new JPanel(new BorderLayout());
                statusLabel = new JLabel("就绪");
                progressBar = new JProgressBar(0, 100);
                progressBar.setStringPainted(true);
                progressBar.setVisible(false);

                statusPanel.add(statusLabel, BorderLayout.WEST);
                statusPanel.add(progressBar, BorderLayout.EAST);
                mainPanel.add(statusPanel, BorderLayout.SOUTH);
                // 注册扩展的选项卡
                callbacks.addSuiteTab(BurpExtender.this);
                log.info("UI初始化完成");
            }
        });

        log.info("所有功能已注册");
    }

    private void updateRequestHeadersForSelected(String key, String value) {
        synchronized (capturedData) {
            capturedData.stream()
                    .filter(RequestResponseInfo::isSelected)
                    .forEach(info -> {
                        IHttpRequestResponse messageInfo = info.getMessageInfo();
                        byte[] originalRequest = messageInfo.getRequest();
                        IRequestInfo requestInfo = helpers.analyzeRequest(originalRequest);
                        int oldBodyOffset = requestInfo.getBodyOffset();
                        byte[] requestBody = Arrays.copyOfRange(originalRequest, oldBodyOffset, originalRequest.length);
                        List<String> headers = requestInfo.getHeaders();
                        List<String> newHeaders = UrlUtil.replaceHeader(key, value, headers);
                        byte[] newRequest = helpers.buildHttpMessage(newHeaders, requestBody);
                        // 重新解析新的请求，获取新的bodyOffset
                        IRequestInfo newRequestInfo = helpers.analyzeRequest(newRequest);
                        int newBodyOffset = newRequestInfo.getBodyOffset();
                        // 用原始 response 字节流
                        byte[] responseBytes = messageInfo.getResponse();
                        // 构建新的 DummyHttpRequestResponse（或你项目里的实现）
                        IHttpRequestResponse newMessageInfo = new burp.http.DummyHttpRequestResponse(
                                newRequest,
                                responseBytes,
                                messageInfo.getHttpService()
                        );
                        info.setMessageInfo(newMessageInfo);

                        // 更新请求头和请求体，保证UI同步
                        info.setRequestHeaders(new String(newRequest, 0, newBodyOffset));
                        info.setRequestBody(new String(newRequest, newBodyOffset, newRequest.length - newBodyOffset));
                    });
            tableModel.fireTableDataChanged();
        }
    }

    /**
     * 返回在Burp界面中显示的标签页名称
     *
     * @return 标签页名称
     */
    @Override
    public String getTabCaption() {
        return "安全手工测试辅助工具";
    }

    /**
     * 返回扩展的UI组件，用于在Burp界面中显示
     *
     * @return UI组件
     */
    @Override
    public Component getUiComponent() {
        return mainPanel;
    }

    /**
     * 处理HTTP消息的回调方法，用于捕获代理工具的响应数据
     *
     * @param toolFlag         指示消息来源的工具标识
     * @param messageIsRequest 指示消息是请求还是响应
     * @param messageInfo      HTTP消息的详细信息
     */
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // 只处理代理工具的响应数据
        if (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY && !messageIsRequest) {
            try {
                // 获取URL以检查后缀
                IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
                String url = requestInfo.getUrl().toString();

                // 检查是否应该排除此URL（基于扩展名和关键词）
                if (KeyWordUtils.shouldExcludeUrl(url, excludeExtensionsField.getText()) || KeyWordUtils.shouldExcludeUrlByKeywords(url, excludeUrlKeywordsField.getText())) {
                    log.info("排除URL: {}", url);
                    return;
                }
                // 添加调试日志
                log.info("捕获到请求: {}", url);

                // 对URL进行规范化处理，以便去重（可选择是否移除URL参数）
                String normalizedUrl = url;

                // 检查是否启用URL去重 - 添加安全检查
                boolean enableDeduplication = false;
                try {
                    enableDeduplication = enableUrlDeduplicationCheckBox != null && enableUrlDeduplicationCheckBox.isSelected();
                } catch (Exception e) {
                    log.error("检查URL去重设置时出错: {}", e.getMessage());
                    // 默认启用去重，以防万一UI组件尚未初始化
                    enableDeduplication = true;
                }

                if (enableDeduplication) {
                    normalizedUrl = UrlUtil.normalizeUrlForDeduplication(url);
                }
                //加锁
                synchronized (capturedData) {
                    // 如果启用了URL去重，检查是否已经存在相同的URL
                    if (enableDeduplication) {
                        if (uniqueUrls.contains(normalizedUrl)) {
                            log.info("重复URL，已跳过: {}", url);
                            return;
                        }
                        // 添加到去重集合
                        uniqueUrls.add(normalizedUrl);
                    }

                    RequestResponseInfo info = new RequestResponseInfo(this.helpers, messageInfo, capturedData.size() + 1);
                    capturedData.add(info);

                    // 更新表格 (需要在EDT线程中执行)
                    SwingUtilities.invokeLater(() -> {
                        log.info("更新表格，当前数据行数: {}", capturedData.size());
                        tableModel.fireTableDataChanged();
                    });
                }
            } catch (Exception e) {
                log.error("处理HTTP消息时出错: {}", e.getMessage());
            }
        }
    }

    /**
     * 清空已捕获的数据并刷新表格
     */
    private void clearData() {
        synchronized (capturedData) {
            capturedData.removeIf(RequestResponseInfo::isSelected);
            capturedData.stream().map(info -> UrlUtil.normalizeUrlForDeduplication(info.getUrl())).forEach(uniqueUrls::remove);
            tableModel.fireTableDataChanged();
            log.info("已清空记录");
        }
    }

    /**
     * 导出选中的请求数据到CSV
     */
    private void exportData() {
        List<RequestResponseInfo> selectedData = new ArrayList<>();
        //判断是否选中
        synchronized (capturedData) {
            for (RequestResponseInfo info : capturedData) {
                if (info.isSelected()) {
                    selectedData.add(info);
                }
            }
        }
        if (selectedData.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, "没有选择任何数据！", "错误", JOptionPane.ERROR_MESSAGE);
            log.warn("导出失败：没有选择任何数据");
            return;
        }
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setFileFilter(new FileNameExtensionFilter("JSON 文件 (*.json)", "json"));
        fileChooser.setSelectedFile(new File("burp_export.json"));
        int result = fileChooser.showSaveDialog(mainPanel);
        if (result == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            String filePath = selectedFile.getAbsolutePath();
            // 确保文件扩展名正确
            if (!filePath.toLowerCase().endsWith(".json")) {
                filePath += ".json";
            }
            try {
                FileUtils.exportToJsonFile(filePath, selectedData);
                JOptionPane.showMessageDialog(mainPanel, "导出成功！", "信息", JOptionPane.INFORMATION_MESSAGE);
                log.info("成功导出 {} 条记录到文件: {}", selectedData.size(), filePath);
            } catch (IOException e) {
                JOptionPane.showMessageDialog(mainPanel, "导出失败：" + e.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
                log.error("导出失败: {}", e.getMessage());
            }
        } else {
            log.info("用户取消了文件选择");
        }
    }

    /**
     * 导入请求数据
     */
    private void importData() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("选择导入文件");
        fileChooser.setFileFilter(new FileNameExtensionFilter("JSON 文件 (*.json)", "json"));
        int result = fileChooser.showOpenDialog(mainPanel);
        if (result == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            try {
                String fileName = selectedFile.getName().toLowerCase();
                if (fileName.endsWith(".json")) {
                    importFromCSV(selectedFile.getAbsolutePath());
                } else {
                    JOptionPane.showMessageDialog(mainPanel, "不支持的文件格式，只支持json格式", "错误", JOptionPane.ERROR_MESSAGE);
                }
            } catch (Exception e) {
                JOptionPane.showMessageDialog(mainPanel, "导入失败: " + e.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
                log.error("导入失败", e);
            }
        }
    }

    /**
     * 从CSV文件导入数据
     */
    private void importFromCSV(String filePath) throws IOException {
        log.info("开始从json文件导入数据: " + filePath);
        List<RequestResponseInfo> importedData = new ArrayList<>();

        String ip = ipTextField.getText().trim();
        String port = portTextField.getText().trim();
        // 创建cookie更新设置对话框
        boolean updateRequestHeaders = false;
        boolean updateCookies = false;
        String cookieDomain = "";

        if (!ip.isEmpty() || !port.isEmpty()) {
            // 如果要更新IP或端口，提示是否同步更新请求头
            JPanel optionsPanel = new JPanel();
            optionsPanel.setLayout(new GridLayout(3, 1));

            JCheckBox updateHeadersCheckBox = new JCheckBox("同步更新请求头中的Host信息");
            updateHeadersCheckBox.setSelected(true);
            optionsPanel.add(updateHeadersCheckBox);

            JCheckBox updateCookiesCheckBox = new JCheckBox("同步更新Cookie中的域信息");
            JTextField cookieDomainField = new JTextField(20);

            JPanel cookiePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            cookiePanel.add(updateCookiesCheckBox);
            optionsPanel.add(cookiePanel);

            JPanel domainPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
            domainPanel.add(new JLabel("Cookie域名: "));
            domainPanel.add(cookieDomainField);
            optionsPanel.add(domainPanel);

            // 如果提供了IP，则预填充cookie域名
            if (!ip.isEmpty()) {
                cookieDomainField.setText(ip);
            }

            updateCookiesCheckBox.addActionListener(e -> {
                cookieDomainField.setEnabled(updateCookiesCheckBox.isSelected());
            });

            // 默认选中Cookie域更新选项，并启用域名输入框
            updateCookiesCheckBox.setSelected(true);
            cookieDomainField.setEnabled(true);

            int result = JOptionPane.showConfirmDialog(mainPanel, optionsPanel, "请求头更新选项", JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE);

            if (result == JOptionPane.OK_OPTION) {
                updateRequestHeaders = updateHeadersCheckBox.isSelected();
                updateCookies = updateCookiesCheckBox.isSelected();
                cookieDomain = cookieDomainField.getText().trim();

                log.info("导入设置 - 更新请求头Host: " + (updateRequestHeaders ? "是" : "否") + ", 更新Cookie域: " + (updateCookies ? "是，域=" + cookieDomain : "否"));
            }
        }

        log.info("导入设置 - IP替换: " + (ip.isEmpty() ? "否" : ip) + ", 端口替换: " + (port.isEmpty() ? "否" : port));


        // 读取文件内容（去除 BOM）
        StringBuilder jsonBuilder = new StringBuilder();
        try (BufferedReader reader = Files.newBufferedReader(Paths.get(filePath), StandardCharsets.UTF_8)) {
            int ch;
            boolean isFirstChar = true;
            while ((ch = reader.read()) != -1) {
                if (isFirstChar && ch == 0xFEFF) {
                    // 跳过 UTF-8 BOM
                    continue;
                }
                isFirstChar = false;
                jsonBuilder.append((char) ch);
            }
        }
        String jsonContent = jsonBuilder.toString();
        JSONArray array = JSON.parseArray(jsonContent);

        for (int i = 0; i < array.size(); i++) {
            JSONObject obj = array.getJSONObject(i);
            int id = capturedData.size() + importedData.size() + 1;
            String method = obj.getString("method");
            String url = obj.getString("url");
            int statusCode = obj.getIntValue("status");
            String requestHeaders = obj.getString("requestHeaders");
            String requestBody = obj.getString("requestBody");
            String responseBody = obj.getString("responseBody");

            String originalUrl = url;
            // 替换IP和端口（如果指定）
            if (!ip.isEmpty() && !port.isEmpty()) {
                url = UrlUtil.replaceHostAndPort(url, ip, port);
                log.info("第" + i + 1 + "行 - 替换IP和端口: " + originalUrl + " -> " + url);
            } else if (!ip.isEmpty()) {
                url = UrlUtil.replaceHost(url, ip);
                log.info("第" + i + 1 + "行 - 替换IP: " + originalUrl + " -> " + url);
            } else if (!port.isEmpty()) {
                url = UrlUtil.replacePort(url, port);
                log.info("第" + i + 1 + "行 - 替换端口: " + originalUrl + " -> " + url);
            }

            // 处理请求头更新
            if (updateRequestHeaders || updateCookies) {
                requestHeaders = UrlUtil.updateRequestHeaders(originalUrl, url, requestHeaders, updateRequestHeaders, updateCookies, cookieDomain);
                log.info("第" + i + 1 + "行 - 已更新请求头: " + (updateRequestHeaders ? "Host" : "") + (updateCookies ? " Cookies" : ""));
            }
            IHttpRequestResponse messageInfo = httpServiceUtil.createFormattedHttpRequestResponse(url, statusCode, requestHeaders, requestBody, responseBody);

            RequestResponseInfo info = new RequestResponseInfo(this.helpers, messageInfo, id);
            // 手动设置一些字段
            info.setUrl(url);
            info.setMethod(method);
            info.setStatusCode(statusCode);
            info.setRequestHeaders(requestHeaders);
            info.setRequestBody(MultipartFixer.fixIfMultipart(requestBody));
            info.setResponseBody(responseBody);
            importedData.add(info);
        }
        if (!importedData.isEmpty()) {
            capturedData.addAll(importedData);
            TableRowSorter<RequestTableModel> sorter = new TableRowSorter<>(tableModel);
            requestsTable.setRowSorter(sorter);
            // 清除所有筛选条件
            sorter.setRowFilter(null);
            // 强制刷新表格
            tableModel.fireTableDataChanged();
            // 滚动到新导入的数据的位置
            if (requestsTable.getRowCount() > 0) {
                int lastRow = requestsTable.getRowCount() - 1;
                requestsTable.scrollRectToVisible(requestsTable.getCellRect(lastRow, 0, true));
                // 选中最后导入的一行
                requestsTable.setRowSelectionInterval(lastRow - importedData.size() + 1, lastRow);
            }
            // 切换到请求面板
            tabbedPane.setSelectedComponent(requestPanel);
            JOptionPane.showMessageDialog(mainPanel, "成功导入 " + importedData.size() + " 条记录", "导入成功", JOptionPane.INFORMATION_MESSAGE);
        } else {
            JOptionPane.showMessageDialog(mainPanel, "没有可导入的数据", "警告", JOptionPane.WARNING_MESSAGE);
        }
    }

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        return List.of();
    }


    /**
     * 清空未授权测试结果
     */
    private void clearAuthTestResults() {
        authTestResults.clear();
        authTestTableModel.fireTableDataChanged();
        requestViewer.setText("");
        responseViewer.setText("");
        log.info("已清空未授权测试结果");
    }

    /**
     * 测试未授权访问，移除Cookie后重新发送请求
     */
    private void testUnauthorizedAccess() {
        //更新安全关键词
        vulnEngine.setGeneralSafeKeywords(authSafeKeywords);
        // 获取选中的请求
        final List<RequestResponseInfo> selectedData = new ArrayList<>();
        //测试请求列表首页的选中数据
        synchronized (capturedData) {
            for (RequestResponseInfo info : capturedData) {
                if (info.isSelected()) {
                    selectedData.add(info);
                }
            }
        }

        if (selectedData.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, "请选择要测试的请求！", "错误", JOptionPane.ERROR_MESSAGE);
            log.warn("未授权测试失败：没有选择任何请求");
            return;
        }

        // 首次点击时切换到未授权测试结果标签页
        tabbedPane.setSelectedComponent(authTestPanel);

        // 显示进度条并设置初始状态
        SwingUtilities.invokeLater(() -> {
            progressBar.setValue(0);
            progressBar.setVisible(true);
            statusLabel.setText("正在测试未授权访问...");
        });

        // 创建独立线程处理HTTP请求，避免在EDT线程中执行
        new Thread(() -> {
            try {
                // 处理每个选中的请求
                final int totalRequests = selectedData.size();
                for (int i = 0; i < selectedData.size(); i++) {
                    final RequestResponseInfo info = selectedData.get(i);
                    final int currentIndex = i;
                    // 更新进度
                    SwingUtilities.invokeLater(() -> {
                        int progress = (int) ((currentIndex * 100.0) / totalRequests);
                        progressBar.setValue(progress);
                        statusLabel.setText("正在测试未授权访问... (" + (currentIndex + 1) + "/" + totalRequests + ")");
                    });

                    try {
                        // 获取原始请求信息
                        IHttpRequestResponse messageInfo = info.getMessageInfo();
                        byte[] originalRequest = messageInfo.getRequest();
                        IRequestInfo requestInfo = helpers.analyzeRequest(originalRequest);

                        // 复制请求体
                        int bodyOffset = requestInfo.getBodyOffset();
                        byte[] requestBody = Arrays.copyOfRange(originalRequest, bodyOffset, originalRequest.length);

                        // 构建新请求头，去掉 Cookie
                        List<String> newHeaders = requestInfo.getHeaders().stream()
                                .map(String::trim)  // 去除每个 header 的前后空格
                                .filter(header -> {
                                    String lower = header.toLowerCase();
                                    return !lower.startsWith("cookie:") && !lower.startsWith("authorization:");
                                })
                                .collect(Collectors.toList());

                        requestInfo.getHeaders().stream()
                                .map(String::toLowerCase)
                                .forEach(header -> {
                                    if (header.startsWith("cookie:")) {
                                        newHeaders.add("Cookie:");  // 如果原请求包含 Cookie，则添加空的 Cookie
                                    }
                                    if (header.startsWith("authorization:")) {
                                        newHeaders.add("Authorization:");  // 如果原请求包含 Authorization，则添加空的 Authorization
                                    }
                                });


                        //todo 需要确定一下是否需要最后的换行  确定：需要

                        // 构造新的请求
                        byte[] newRequest = helpers.buildHttpMessage(newHeaders, requestBody);

                        // 发送新请求
                        IHttpRequestResponse newResponse = callbacks.makeHttpRequest(messageInfo.getHttpService(), newRequest);

                        // 提取新请求内容
                        byte[] requestBytes = newResponse.getRequest();
                        IRequestInfo modifiedRequestInfo = helpers.analyzeRequest(requestBytes);
                        int modifiedBodyOffset = modifiedRequestInfo.getBodyOffset();
                        String requestHeadersStr = new String(requestBytes, 0, modifiedBodyOffset, StandardCharsets.UTF_8);
                        String requestBodyStr = new String(requestBytes, modifiedBodyOffset, requestBytes.length - modifiedBodyOffset, StandardCharsets.UTF_8);

                        // 提取响应信息
                        byte[] responseBytes = newResponse.getResponse();
                        String responseHeadersStr = "";
                        String responseBodyStr = "";
                        int statusCode = -1;

                        if (responseBytes != null && responseBytes.length > 0) {
                            IResponseInfo responseInfo = helpers.analyzeResponse(responseBytes);
                            int responseBodyOffset = responseInfo.getBodyOffset();
                            statusCode = responseInfo.getStatusCode();

                            responseHeadersStr = new String(responseBytes, 0, responseBodyOffset, StandardCharsets.UTF_8);
                            responseBodyStr = new String(responseBytes, responseBodyOffset, responseBytes.length - responseBodyOffset, StandardCharsets.UTF_8);
                        }

                        // 判断是否存在漏洞
                        VulnerabilityDetectionEngine.VulnerabilityResult result = vulnEngine.detectAuthVulnerability(statusCode, responseBytes);

                        final boolean isVulnerable = result.isVulnerable();
                        final boolean needsConfirmation = result.isNeedsConfirmation();

                        // 记录判断原因
                        log.info("URL: {} 漏洞判断结果: {}, 原因: {}", info.getUrl(), isVulnerable ? "存在漏洞" : (needsConfirmation ? "需要确认" : "安全"), result.getReason());

                        // 创建测试结果对象
                        final AuthTestResult testResult = new AuthTestResult(
                                authTestResults.size() + 1,
                                info.getUrl(),
                                statusCode,
                                isVulnerable,
                                needsConfirmation,
                                false,
                                requestHeadersStr,
                                requestBodyStr, //最好采用标准的
                                responseHeadersStr,
                                responseBodyStr,
                                result.getReason());

                        // 创建新的记录并更新UI（在EDT线程中）
                        int finalStatusCode = statusCode;
                        SwingUtilities.invokeLater(() -> {
                            // 检查是否已存在相同URL的测试结果
                            boolean isDuplicate = false;
                            for (AuthTestResult existingResult : authTestResults) {
                                if (existingResult.getUrl().equals(testResult.getUrl())) {
                                    isDuplicate = true;
                                    // 更新现有结果
                                    existingResult.setStatusCode(testResult.getStatusCode());
                                    existingResult.setVulnerable(testResult.isVulnerable());
                                    existingResult.setNeedsConfirmation(testResult.isNeedsConfirmation());
                                    existingResult.setRequestHeaders(testResult.getRequestHeaders());
                                    existingResult.setRequestBody(testResult.getRequestBody());
                                    existingResult.setResponseHeaders(testResult.getResponseHeaders());
                                    existingResult.setResponseBody(testResult.getResponseBody());
                                    log.info("更新已存在的测试结果 - URL: {}", existingResult.getUrl());
                                    break;
                                }
                            }

                            // 如果不是重复的，则添加到测试结果列表
                            if (!isDuplicate) {
                                authTestResults.add(testResult);
                                log.info("添加新的测试结果 - URL: " + testResult.getUrl());
                            }

                            // 重新排序ID，确保序号连续
                            for (int i1 = 0; i1 < authTestResults.size(); i1++) {
                                authTestResults.get(i1).setId(i1 + 1);
                            }

                            // 更新表格
                            authTestTableModel.fireTableDataChanged();

                            // 记录结果
                            String resultMsg;
                            if (isVulnerable) {
                                resultMsg = "可能存在未授权访问漏洞";
                            } else if (needsConfirmation) {
                                resultMsg = "需要人工确认（状态码: " + finalStatusCode + "）";
                            } else {
                                resultMsg = "未授权访问测试失败";
                            }
                            log.info("未授权访问测试结果 - URL: " + info.getUrl() + ", 状态码: " + finalStatusCode + ", 结果: " + resultMsg);
                        });

                    } catch (Exception e) {
                        log.error("测试未授权访问时出错: " + e.getMessage());
                    }
                }

                // 测试完成后，更新UI
                SwingUtilities.invokeLater(() -> {
                    progressBar.setValue(100);
                    statusLabel.setText("未授权访问测试完成，共测试 " + totalRequests + " 个请求");

                    // 3秒后隐藏进度条
                    new Timer(3000, e -> {
                        progressBar.setVisible(false);
                        statusLabel.setText("就绪");
                        ((Timer) e.getSource()).stop();
                    }).start();

                    JOptionPane.showMessageDialog(mainPanel, "未授权访问测试完成，结果已添加到列表中。\n您可以在「未授权测试结果」标签页查看详细信息。", "信息", JOptionPane.INFORMATION_MESSAGE);
                });
            } catch (Exception e) {
                log.error("测试未授权访问过程中出错: " + e.getMessage());
                e.printStackTrace();

                // 出错时也要隐藏进度条
                SwingUtilities.invokeLater(() -> {
                    progressBar.setVisible(false);
                    statusLabel.setText("测试未授权访问时出错: " + e.getMessage());
                });
            }
        }, "UnauthorizedAccessTester").start();
    }

    /**
     * 测试CSRF漏洞，修改Referer后重新发送请求
     */
    private void testCsrfVulnerability() {
        vulnEngine.setCsrfSafeKeywords(csrfSafeKeywords);
        // 获取选中的请求
        final List<RequestResponseInfo> selectedData = new ArrayList<>();
        synchronized (capturedData) {
            for (RequestResponseInfo info : capturedData) {
                if (info.isSelected()) {
                    selectedData.add(info);
                }
            }
        }

        if (selectedData.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, "请选择要测试的请求！", "错误", JOptionPane.ERROR_MESSAGE);
            log.warn("CSRF测试失败：没有选择任何请求");
            return;
        }

        // 首次点击时切换到CSRF测试结果标签页
        tabbedPane.setSelectedComponent(csrfTestPanel);

        // 显示进度条并设置初始状态
        SwingUtilities.invokeLater(() -> {
            progressBar.setValue(0);
            progressBar.setVisible(true);
            statusLabel.setText("正在测试CSRF漏洞...");
        });

        // 弹出对话框，让用户选择如何修改Referer
        String[] options = {"移除Referer", "使用自定义Referer", "使用随机域名Referer"};
        int choice = JOptionPane.showOptionDialog(mainPanel, "请选择如何修改Referer头：", "CSRF测试", JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE, null, options, options[0]);

        if (choice == JOptionPane.CLOSED_OPTION) {
            // 用户关闭了对话框，取消测试
            SwingUtilities.invokeLater(() -> {
                progressBar.setVisible(false);
                statusLabel.setText("就绪");
            });
            return;
        }

        // 如果选择使用自定义Referer，则弹出输入框
        final String customReferer;
        if (choice == 1) {
            customReferer = JOptionPane.showInputDialog(mainPanel, "请输入自定义Referer值：", "https://attacker-site.com");
            if (customReferer == null || customReferer.trim().isEmpty()) {
                // 用户取消了输入，取消测试
                SwingUtilities.invokeLater(() -> {
                    progressBar.setVisible(false);
                    statusLabel.setText("就绪");
                });
                return;
            }
        } else {
            customReferer = null;
        }

        // 创建独立线程处理HTTP请求，避免在EDT线程中执行
        new Thread(() -> {
            try {
                // 处理每个选中的请求
                final int totalRequests = selectedData.size();
                for (int i = 0; i < selectedData.size(); i++) {
                    final RequestResponseInfo info = selectedData.get(i);
                    final int currentIndex = i;

                    // 更新进度
                    SwingUtilities.invokeLater(() -> {
                        int progress = (int) ((currentIndex * 100.0) / totalRequests);
                        progressBar.setValue(progress);
                        statusLabel.setText("正在测试CSRF漏洞... (" + (currentIndex + 1) + "/" + totalRequests + ")");
                    });

                    try {
                        // 获取原始请求
                        IHttpRequestResponse messageInfo = info.getMessageInfo();
                        byte[] originalRequest = messageInfo.getRequest();
                        IRequestInfo requestInfo = helpers.analyzeRequest(originalRequest);


                        // 获取所有请求头
                        List<String> headers = requestInfo.getHeaders();
                        List<String> newHeaders = new ArrayList<>();

                        // 修改的Referer值
                        String modifiedReferer = "";

                        // 处理请求头
                        boolean refererFound = false;
                        for (String header : headers) {
                            if (header.toLowerCase().startsWith("referer:")) {
                                refererFound = true;
                                // 根据用户选择修改Referer
                                if (choice == 0) {
                                    // 不添加这个头，相当于移除Referer
                                    modifiedReferer = "[已移除]";
                                } else if (choice == 1) {
                                    // 使用自定义Referer
                                    newHeaders.add("Referer: " + customReferer);
                                    modifiedReferer = customReferer;
                                } else if (choice == 2) {
                                    // 使用随机域名
                                    String randomDomain = "https://random-" + System.currentTimeMillis() + ".com";
                                    newHeaders.add("Referer: " + randomDomain);
                                    modifiedReferer = randomDomain;
                                }
                            } else {
                                newHeaders.add(header);
                            }
                        }

                        // 如果原请求没有Referer头，但选择了添加自定义或随机Referer
                        if (!refererFound && (choice == 1 || choice == 2)) {
                            String refererValue;
                            if (choice == 1) {
                                refererValue = customReferer;
                            } else {
                                refererValue = "https://random-" + System.currentTimeMillis() + ".com";
                            }
                            newHeaders.add("Referer: " + refererValue);
                            modifiedReferer = refererValue;
                        }

                        log.info("修改Referer，准备重新发送请求: {}", info.getUrl());

                        // 重建请求（保持请求体不变）
                        byte[] body = new byte[originalRequest.length - requestInfo.getBodyOffset()];
                        System.arraycopy(originalRequest, requestInfo.getBodyOffset(), body, 0, body.length);
                        byte[] newRequest = helpers.buildHttpMessage(newHeaders, body);

                        // 发送新请求
                        final IHttpRequestResponse newResponse = callbacks.makeHttpRequest(messageInfo.getHttpService(), newRequest);

                        // 分析响应
                        byte[] responseBytes = newResponse.getResponse();
                        IResponseInfo responseInfo = helpers.analyzeResponse(responseBytes);
                        final int statusCode = responseInfo.getStatusCode();

                        // 获取请求头和响应头
                        byte[] requestBytes = newResponse.getRequest();
                        byte[] responseBytes2 = newResponse.getResponse();

                        // 解析请求
                        IRequestInfo modifiedRequestInfo = helpers.analyzeRequest(requestBytes);
                        int modifiedBodyOffset = modifiedRequestInfo.getBodyOffset();

                        // 解析请求头和请求体
                        String requestHeadersStr = new String(requestBytes, 0, modifiedBodyOffset);
                        String requestBodyStr = "";
                        if (requestBytes.length > modifiedBodyOffset) {
                            requestBodyStr = new String(requestBytes, modifiedBodyOffset, requestBytes.length - modifiedBodyOffset);
                        }

                        // 解析响应头和响应体
                        String responseHeadersStr = "";
                        String responseBodyStr = "";
                        if (responseBytes2 != null && responseBytes2.length > 0) {
                            int responseBodyOffset = responseInfo.getBodyOffset();
                            responseHeadersStr = new String(responseBytes2, 0, responseBodyOffset);
                            responseBodyStr = new String(responseBytes2, responseBodyOffset, responseBytes2.length - responseBodyOffset);
                        }

                        // 判断是否存在漏洞
                        VulnerabilityDetectionEngine.VulnerabilityResult result = vulnEngine.detectCsrfVulnerability(statusCode, responseBytes2, info.getMethod());

                        final boolean isVulnerable = result.isVulnerable();
                        final boolean needsConfirmation = result.isNeedsConfirmation();

                        // 记录判断原因
                        log.info("URL: {} 漏洞判断结果: {}, 原因: {}", info.getUrl(), isVulnerable ? "存在漏洞" : (needsConfirmation ? "需要确认" : "安全"), result.getReason());
                        // 创建测试结果对象
                        final CsrfTestResult testResult = new CsrfTestResult(csrfTestResults.size() + 1, info.getUrl(), statusCode, isVulnerable, needsConfirmation, false, requestHeadersStr, requestBodyStr, responseHeadersStr, responseBodyStr, modifiedReferer, result.getReason());

                        // 创建新的记录并更新UI（在EDT线程中）
                        SwingUtilities.invokeLater(new Runnable() {
                            @Override
                            public void run() {
                                // 检查是否有重复的URL，如果有则更新而不是添加
                                boolean isDuplicate = false;
                                for (int i = 0; i < csrfTestResults.size(); i++) {
                                    CsrfTestResult existingResult = csrfTestResults.get(i);
                                    if (existingResult.getUrl().equals(testResult.getUrl())) {
                                        csrfTestResults.set(i, testResult);
                                        isDuplicate = true;
                                        log.info("更新已存在的CSRF测试结果 - URL: " + existingResult.getUrl());
                                        break;
                                    }
                                }

                                if (!isDuplicate) {
                                    csrfTestResults.add(testResult);
                                    log.info("添加新的CSRF测试结果 - URL: " + testResult.getUrl());
                                }

                                // 重新排序ID，确保序号连续
                                for (int i = 0; i < csrfTestResults.size(); i++) {
                                    csrfTestResults.get(i).setId(i + 1);
                                }

                                // 更新表格
                                csrfTestTableModel.fireTableDataChanged();

                                // 显示简短的测试结果
                                String resultMsg;
                                if (testResult.isVulnerable()) {
                                    resultMsg = "可能存在CSRF漏洞";
                                } else if (testResult.isNeedsConfirmation()) {
                                    resultMsg = "需要进一步确认";
                                } else {
                                    resultMsg = "CSRF测试未发现问题";
                                }
                                log.info("CSRF测试结果 - URL: " + info.getUrl() + ", 状态码: " + statusCode + ", 结果: " + resultMsg);
                            }
                        });

                    } catch (Exception e) {
                        log.error("测试CSRF漏洞时出错: " + e.getMessage());
                    }
                }

                // 测试完成后，更新UI
                SwingUtilities.invokeLater(() -> {
                    progressBar.setValue(100);
                    statusLabel.setText("CSRF漏洞测试完成，共测试 " + totalRequests + " 个请求");

                    // 3秒后隐藏进度条
                    new Timer(3000, e -> {
                        progressBar.setVisible(false);
                        statusLabel.setText("就绪");
                        ((Timer) e.getSource()).stop();
                    }).start();

                    JOptionPane.showMessageDialog(mainPanel, "CSRF测试完成，结果已添加到列表中。\n您可以在「CSRF测试结果」标签页查看详细信息。", "信息", JOptionPane.INFORMATION_MESSAGE);
                });
            } catch (Exception e) {
                log.error("测试CSRF漏洞过程中出错: " + e.getMessage());
                e.printStackTrace();

                // 出错时也要隐藏进度条
                SwingUtilities.invokeLater(() -> {
                    progressBar.setVisible(false);
                    statusLabel.setText("测试CSRF漏洞时出错: " + e.getMessage());
                });
            }
        }, "CsrfVulnerabilityTester").start();
    }

    /**
     * 测试不安全HTTP方法漏洞
     * 通过将原始请求方法更改为PUT、DELETE、HEAD等方法，检测服务器是否存在不当处理
     */
    private void testUnsafeHttpMethods() {
        vulnEngine.setMethodSafeKeywords(methodSafeKeywords);
        // 获取选中的请求
        final List<RequestResponseInfo> selectedData = new ArrayList<>();
        synchronized (capturedData) {
            for (RequestResponseInfo info : capturedData) {
                if (info.isSelected()) {
                    selectedData.add(info);
                }
            }
        }

        if (selectedData.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, "请选择要测试的请求！", "错误", JOptionPane.ERROR_MESSAGE);
            log.warn("不安全HTTP方法测试失败：没有选择任何请求");
            return;
        }

        // 切换到不安全HTTP方法测试结果标签页
        tabbedPane.setSelectedIndex(3); // 假设不安全HTTP方法测试结果是第四个标签页

        // 显示进度条并设置初始状态
        SwingUtilities.invokeLater(() -> {
            progressBar.setValue(0);
            progressBar.setVisible(true);
            statusLabel.setText("正在准备测试不安全HTTP方法...");
        });

        // 弹出对话框，让用户选择要测试的HTTP方法
        String[] httpMethods = {"PUT", "DELETE", "HEAD", "OPTIONS", "TRACE", "PATCH", "CONNECT"};
        JList<String> methodList = new JList<>(httpMethods);
        methodList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        methodList.setSelectedIndices(new int[]{0, 1, 2}); // 默认选择PUT、DELETE和HEAD

        JScrollPane scrollPane = new JScrollPane(methodList);
        scrollPane.setPreferredSize(new Dimension(250, 150));

        int result = JOptionPane.showConfirmDialog(mainPanel, scrollPane, "选择要测试的HTTP方法", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

        if (result != JOptionPane.OK_OPTION) {
            // 用户取消了操作，隐藏进度条
            SwingUtilities.invokeLater(() -> {
                progressBar.setVisible(false);
                statusLabel.setText("就绪");
            });
            return;
        }

        // 获取用户选择的HTTP方法
        final List<String> selectedMethods = methodList.getSelectedValuesList();
        if (selectedMethods.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, "请至少选择一种HTTP方法！", "错误", JOptionPane.ERROR_MESSAGE);
            // 没有选择方法，隐藏进度条
            SwingUtilities.invokeLater(() -> {
                progressBar.setVisible(false);
                statusLabel.setText("就绪");
            });
            return;
        }

        // 创建独立线程处理HTTP请求，避免在EDT线程中执行
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    // 计算总共要进行的测试数量
                    final int totalTests = selectedData.size() * selectedMethods.size();
                    int currentTestIndex = 0;

                    // 处理每个选中的请求
                    for (final RequestResponseInfo info : selectedData) {
                        // 对每个选中的方法进行测试
                        for (final String method : selectedMethods) {
                            final int testIndex = ++currentTestIndex;

                            // 更新进度
                            SwingUtilities.invokeLater(() -> {
                                int progress = (int) ((testIndex * 100.0) / totalTests);
                                progressBar.setValue(progress);
                                statusLabel.setText("正在测试不安全HTTP方法... (" + testIndex + "/" + totalTests + ")");
                            });

                            try {
                                // 获取原始请求
                                IHttpRequestResponse messageInfo = info.getMessageInfo();
                                byte[] originalRequest = messageInfo.getRequest();
                                IRequestInfo requestInfo = helpers.analyzeRequest(originalRequest);

                                // 创建修改后的请求头
                                List<String> headers = requestInfo.getHeaders();
                                List<String> newHeaders = new ArrayList<>();

                                // 替换请求方法
                                String firstLine = headers.get(0);
                                String originalMethod = info.getMethod();
                                String newFirstLine = firstLine.replaceFirst(originalMethod, method);
                                newHeaders.add(newFirstLine);

                                // 添加其他头信息
                                for (int i = 1; i < headers.size(); i++) {
                                    newHeaders.add(headers.get(i));
                                }

                                log.info("测试不安全HTTP方法 " + method + " 于URL: " + info.getUrl());

                                // 重建请求（保持请求体不变）
                                byte[] body = new byte[originalRequest.length - requestInfo.getBodyOffset()];
                                System.arraycopy(originalRequest, requestInfo.getBodyOffset(), body, 0, body.length);
                                byte[] newRequest = helpers.buildHttpMessage(newHeaders, body);

                                // 发送新请求
                                final IHttpRequestResponse newResponse = callbacks.makeHttpRequest(messageInfo.getHttpService(), newRequest);

                                // 分析响应
                                byte[] responseBytes = newResponse.getResponse();
                                IResponseInfo responseInfo = helpers.analyzeResponse(responseBytes);
                                final int statusCode = responseInfo.getStatusCode();

                                // 获取请求头和响应头
                                byte[] requestBytes = newResponse.getRequest();
                                byte[] responseBytes2 = newResponse.getResponse();

                                // 解析请求
                                IRequestInfo modifiedRequestInfo = helpers.analyzeRequest(requestBytes);
                                int modifiedBodyOffset = modifiedRequestInfo.getBodyOffset();

                                // 解析请求头和请求体
                                String requestBodyStr = "";
                                String requestHeadersStr = new String(requestBytes, 0, modifiedBodyOffset);
                                if (requestBytes.length > modifiedBodyOffset) {
                                    requestBodyStr = new String(requestBytes, modifiedBodyOffset, requestBytes.length - modifiedBodyOffset);
                                }

                                // 解析响应头和响应体
                                String responseHeadersStr = "";
                                String responseBodyStr = "";
                                if (responseBytes2 != null && responseBytes2.length > 0) {
                                    int responseBodyOffset = responseInfo.getBodyOffset();
                                    responseHeadersStr = new String(responseBytes2, 0, responseBodyOffset);
                                    responseBodyStr = new String(responseBytes2, responseBodyOffset, responseBytes2.length - responseBodyOffset);
                                }
                                // 判断是否存在漏洞
                                VulnerabilityDetectionEngine.VulnerabilityResult result = vulnEngine.detectUnsafeMethodVulnerability(statusCode, responseBytes2, method, info.getUrl());

                                final boolean isVulnerable = result.isVulnerable();
                                final boolean needsConfirmation = result.isNeedsConfirmation();

                                // 记录判断原因
                                log.info("URL: {} 漏洞判断结果: {}, 原因: {}", info.getUrl(), isVulnerable ? "存在漏洞" : (needsConfirmation ? "需要确认" : "安全"), result.getReason());

                                // 创建测试结果对象
                                final UnsafeMethodTestResult testResult = new UnsafeMethodTestResult(
                                        unsafeMethodTestResults.size() + 1,
                                        info.getUrl(),
                                        originalMethod,
                                        method,
                                        statusCode,
                                        isVulnerable,
                                        needsConfirmation,
                                        false,
                                        requestHeadersStr,
                                        requestBodyStr,
                                        responseHeadersStr,
                                        responseBodyStr,
                                        result.getReason()
                                );

                                // 创建新的记录并更新UI（在EDT线程中）
                                SwingUtilities.invokeLater(new Runnable() {
                                    @Override
                                    public void run() {
                                        // 检查是否有重复的URL和方法组合，如果有则更新而不是添加
                                        boolean isDuplicate = false;
                                        for (int i = 0; i < unsafeMethodTestResults.size(); i++) {
                                            UnsafeMethodTestResult existingResult = unsafeMethodTestResults.get(i);
                                            if (existingResult.getUrl().equals(testResult.getUrl()) && existingResult.getModifiedMethod().equals(testResult.getModifiedMethod())) {
                                                unsafeMethodTestResults.set(i, testResult);
                                                isDuplicate = true;
                                                log.info("更新已存在的不安全HTTP方法测试结果 - URL: " + existingResult.getUrl() + ", 方法: " + existingResult.getModifiedMethod());
                                                break;
                                            }
                                        }

                                        if (!isDuplicate) {
                                            unsafeMethodTestResults.add(testResult);
                                            log.info("添加新的不安全HTTP方法测试结果 - URL: " + testResult.getUrl() + ", 方法: " + testResult.getModifiedMethod());
                                        }

                                        // 重新排序ID，确保序号连续
                                        for (int i = 0; i < unsafeMethodTestResults.size(); i++) {
                                            unsafeMethodTestResults.get(i).setId(i + 1);
                                        }

                                        // 更新表格
                                        unsafeMethodTestTableModel.fireTableDataChanged();

                                        // 显示简短的测试结果
                                        String resultMsg;
                                        if (testResult.isVulnerable()) {
                                            resultMsg = "可能存在不安全HTTP方法漏洞";
                                        } else if (testResult.isNeedsConfirmation()) {
                                            resultMsg = "需要进一步确认";
                                        } else {
                                            resultMsg = "不安全HTTP方法测试未发现问题";
                                        }
                                        log.info("不安全HTTP方法测试结果 - URL: " + info.getUrl() + ", 方法: " + method + ", 状态码: " + statusCode + ", 结果: " + resultMsg);
                                    }
                                });

                            } catch (Exception e) {
                                log.error("测试不安全HTTP方法时出错: " + e.getMessage());
                            }
                        }
                    }

                    // 测试完成后，更新UI
                    SwingUtilities.invokeLater(() -> {
                        progressBar.setValue(100);
                        statusLabel.setText("不安全HTTP方法测试完成，共测试 " + totalTests + " 个请求");

                        // 3秒后隐藏进度条
                        new Timer(3000, e -> {
                            progressBar.setVisible(false);
                            statusLabel.setText("就绪");
                            ((Timer) e.getSource()).stop();
                        }).start();

                        JOptionPane.showMessageDialog(mainPanel, "不安全HTTP方法测试完成，结果已添加到列表中。\n您可以在「不安全请求测试结果」标签页查看详细信息。", "信息", JOptionPane.INFORMATION_MESSAGE);
                    });
                } catch (Exception e) {
                    log.error("测试不安全HTTP方法过程中出错: " + e.getMessage());
                    e.printStackTrace();

                    // 出错时也要隐藏进度条
                    SwingUtilities.invokeLater(() -> {
                        progressBar.setVisible(false);
                        statusLabel.setText("测试不安全HTTP方法时出错: " + e.getMessage());
                    });
                }
            }
        }, "UnsafeHttpMethodTester").start();
    }

    /**
     * 执行越权测试
     *
     * @param selectedRequests 选中的请求列表
     * @param sessions         测试会话列表
     * @param testType         测试类型（"horizontal" 或 "vertical"）
     * @param manualParams     手动指定的参数列表
     * @param autoDetectParams 是否自动检测参数
     */
    private void performPrivilegeEscalationTest(List<RequestResponseInfo> selectedRequests, List<TestSession> sessions, String testType, String manualParams, boolean autoDetectParams, boolean enableUrlFilter) {
        if (selectedRequests.isEmpty() || sessions.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, "请选择至少一个请求和配置至少一个会话", "错误", JOptionPane.ERROR_MESSAGE);
            return;
        }

        // 检查会话
        List<TestSession> sortedSessions = new ArrayList<>(sessions);
        if ("vertical".equals(testType)) {
            // 垂直越权：按权限级别排序会话
            sortedSessions.sort(Comparator.comparingInt(TestSession::getPrivilegeLevel));
        }

        // 设置进度条
        SwingUtilities.invokeLater(() -> {
            progressBar.setValue(0);
            progressBar.setVisible(true);
            statusLabel.setText("正在执行越权测试...");
        });

        // 在单独的线程中执行测试
        new Thread(() -> {
            try {
                final int totalTests = selectedRequests.size() * (sessions.size() - 1);
                final AtomicInteger testCount = new AtomicInteger(0);

                // 清空现有结果
                privilegeEscalationResults.clear();

                // 对每个请求进行测试
                for (RequestResponseInfo info : selectedRequests) {
                    // 获取原始请求和响应
                    byte[] originalRequest = info.getMessageInfo().getRequest();
                    //原始响应
                    byte[] originalResponse = info.getMessageInfo().getResponse();

                    // 如果启用URL参数过滤，对URL进行处理，移除参数部分
                    String originalUrl = info.getUrl();
                    String filteredUrl = UrlUtil.filterUrl(originalUrl, enableUrlFilter, urlFilterCache);

                    // 在越权测试中，我们主要关注会话替换而非参数修改
                    // 不再需要检查用户标识参数

                    // 水平越权：使用不同用户的相同权限会话进行测试
                    // 垂直越权：使用不同权限级别的会话进行测试
                    for (int i = 0; i < sortedSessions.size(); i++) {
                        TestSession originalSession = sortedSessions.get(i);

                        // 使用原始会话的Cookie/Authorization替换请求中的Cookie/Authorization
                        // 修复: 确保使用原始会话的Cookie替换请求中的Cookie
                        byte[] sessionReplacedRequest = httpServiceUtil.replaceSessionInRequest(originalRequest, getSessionString(originalSession));

                        // 发送原始会话请求并获取响应
                        IHttpRequestResponse originalSessionResponse = callbacks.makeHttpRequest(info.getMessageInfo().getHttpService(), sessionReplacedRequest);

                        // 提取原始请求和响应的详细信息
                        IRequestInfo originalRequestInfo = helpers.analyzeRequest(originalSessionResponse);
                        byte[] originalSessionResponseBytes = originalSessionResponse.getResponse();
                        IResponseInfo originalResponseInfo = helpers.analyzeResponse(originalSessionResponseBytes);
                        int originalStatusCode = originalResponseInfo.getStatusCode();

                        // 解析请求头和请求体
                        int originalBodyOffset = originalRequestInfo.getBodyOffset();
                        String originalRequestHeaders = new String(sessionReplacedRequest, 0, originalBodyOffset);
                        String originalRequestBody = new String(sessionReplacedRequest, originalBodyOffset, sessionReplacedRequest.length - originalBodyOffset);

                        // 解析响应头和响应体
                        int originalResponseBodyOffset = originalResponseInfo.getBodyOffset();
                        String originalResponseHeaders = new String(originalSessionResponseBytes, 0, originalResponseBodyOffset);
                        String originalResponseBody = new String(originalSessionResponseBytes, originalResponseBodyOffset, originalSessionResponseBytes.length - originalResponseBodyOffset);

                        // 对每个其他会话进行测试
                        for (int j = 0; j < sortedSessions.size(); j++) {
                            if (i == j) continue; // 跳过相同的会话

                            TestSession testSession = sortedSessions.get(j);

                            // 垂直越权时，检查权限级别
                            if ("vertical".equals(testType)) {
                                // 对于垂直越权，只测试从低权限到高权限的请求
                                if (testSession.getPrivilegeLevel() >= originalSession.getPrivilegeLevel()) {
                                    continue;
                                }
                            }

                            // 更新进度
                            final int currentTestCount = testCount.incrementAndGet();
                            SwingUtilities.invokeLater(() -> {
                                int progress = (int) ((currentTestCount * 100.0) / totalTests);
                                progressBar.setValue(progress);
                                statusLabel.setText("正在执行越权测试... (" + currentTestCount + "/" + totalTests + ")");
                            });

                            // 仅使用测试会话替换Cookie/Authorization
                            byte[] testSessionRequest = httpServiceUtil.replaceSessionInRequest(originalRequest, getSessionString(testSession));

                            // 发送测试请求并获取响应
                            IHttpRequestResponse testResponse = callbacks.makeHttpRequest(info.getMessageInfo().getHttpService(), testSessionRequest);

                            // 提取测试请求和响应的详细信息
                            IRequestInfo testRequestInfo = helpers.analyzeRequest(testResponse);
                            byte[] testResponseBytes = testResponse.getResponse();
                            IResponseInfo testResponseInfo = helpers.analyzeResponse(testResponseBytes);
                            int testStatusCode = testResponseInfo.getStatusCode();

                            // 解析请求头和请求体
                            int testBodyOffset = testRequestInfo.getBodyOffset();
                            String testRequestHeaders = new String(testSessionRequest, 0, testBodyOffset);
                            String testRequestBody = new String(testSessionRequest, testBodyOffset, testSessionRequest.length - testBodyOffset);

                            // 解析响应头和响应体
                            int testResponseBodyOffset = testResponseInfo.getBodyOffset();
                            String testResponseHeaders = new String(testResponseBytes, 0, testResponseBodyOffset);
                            String testResponseBody = new String(testResponseBytes, testResponseBodyOffset, testResponseBytes.length - testResponseBodyOffset);


                            // 计算响应相似度
                            int similarity = vulnEngine.evaluateBySimilarity(originalSessionResponseBytes, testResponseBytes);
                            // 综合判断是否存在漏洞
                            VulnerabilityDetectionEngine.VulnerabilityResult results = vulnEngine.detectPrivilegeEscalationVulnerability(testStatusCode, testResponseBytes, originalResponse, similarity);

                            final boolean isVulnerable = results.isVulnerable();
                            final boolean needsConfirmation = results.isNeedsConfirmation();

                            // 记录判断原因
                            log.info("URL: {} 漏洞判断结果: {}, 原因: {}", info.getUrl(), isVulnerable ? "存在漏洞" : (needsConfirmation ? "需要确认" : "安全"), results.getReason());


                            // 创建测试结果，使用会话名称作为参数标识
                            final PrivilegeEscalationResult result = new PrivilegeEscalationResult(
                                    privilegeEscalationResults.size() + 1,
                                    enableUrlFilter ? filteredUrl : originalUrl, testType.equals("horizontal") ? "水平越权" : "垂直越权", "会话替换", // 使用会话替换作为参数名
                                    originalSession.getName(), // 原始会话名称
                                    testSession.getName(), // 测试会话名称
                                    originalStatusCode,
                                    testStatusCode,
                                    isVulnerable,
                                    needsConfirmation,
                                    false,
                                    originalRequestHeaders,
                                    originalRequestBody,
                                    originalResponseHeaders,
                                    originalResponseBody,
                                    testRequestHeaders,
                                    testRequestBody,
                                    testResponseHeaders,
                                    testResponseBody,
                                    originalSession,
                                    testSession,
                                    results.getReason());

                            // 添加结果到列表
                            SwingUtilities.invokeLater(() -> {
                                privilegeEscalationResults.add(result);
                                privilegeEscalationTableModel.fireTableDataChanged();

                                // 记录结果
                                String resultMsg;
                                if (result.isVulnerable()) {
                                    resultMsg = "可能存在越权漏洞";
                                } else if (result.isNeedsConfirmation()) {
                                    resultMsg = "需要人工确认（状态码: " + testStatusCode + "）";
                                } else {
                                    resultMsg = "未发现越权漏洞";
                                }

                                log.info("越权测试结果 - URL: " + info.getUrl() + ", 会话替换: " + originalSession.getName() + " -> " + testSession.getName() + ", 状态码: " + testStatusCode + ", 结果: " + resultMsg);
                            });
                        }
                    }
                }

                // 测试完成后，更新UI
                final int finalTestCount = testCount.get();
                SwingUtilities.invokeLater(() -> {
                    progressBar.setValue(100);
                    statusLabel.setText("越权测试完成，共测试 " + finalTestCount + " 个请求");

                    // 3秒后隐藏进度条
                    new Timer(3000, e -> {
                        progressBar.setVisible(false);
                        statusLabel.setText("就绪");
                        ((Timer) e.getSource()).stop();
                    }).start();

                    JOptionPane.showMessageDialog(mainPanel, "越权测试完成，结果已添加到列表中。\n共测试 " + finalTestCount + " 个请求组合。", "信息", JOptionPane.INFORMATION_MESSAGE);
                });
            } catch (Exception e) {
                log.error("执行越权测试过程中出错: " + e.getMessage());
                e.printStackTrace();

                // 出错时也要隐藏进度条
                SwingUtilities.invokeLater(() -> {
                    progressBar.setVisible(false);
                    statusLabel.setText("测试越权时出错: " + e.getMessage());
                });
            }
        }, "PrivilegeEscalationTester").start();
    }

    /**
     * 应用排除过滤条件到已捕获的数据
     */
    private void applyExcludeFilter() {
        synchronized (capturedData) {
            List<RequestResponseInfo> filteredData = new ArrayList<>();
            int originalSize = capturedData.size();

            // 遍历所有捕获的数据
            for (RequestResponseInfo info : capturedData) {
                String url = info.getUrl();
                // 检查是否应该排除（同时检查扩展名和URL关键词）
                if (!KeyWordUtils.shouldExcludeUrl(url, excludeExtensionsField.getText()) && !KeyWordUtils.shouldExcludeUrlByKeywords(url, excludeUrlKeywordsField.getText())) {
                    filteredData.add(info);
                } else {
                    log.info("通过过滤器排除URL: " + url);
                }
            }

            // 更新数据
            capturedData.clear();
            capturedData.addAll(filteredData);
            tableModel.fireTableDataChanged();

            int removedCount = originalSize - capturedData.size();
            log.info("应用排除过滤，移除了 {} 条记录，剩余 {} 条记录", removedCount, capturedData.size());
            JOptionPane.showMessageDialog(mainPanel, "过滤完成，移除了 " + removedCount + " 条记录", "信息", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    /**
     * 确认选中的未授权测试结果
     */
    private void confirmAuthTestResult() {
        int row = authTestResultsTable.getSelectedRow();
        if (row < 0) {
            JOptionPane.showMessageDialog(mainPanel, "请选择要确认的测试结果", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        int modelRow = authTestResultsTable.convertRowIndexToModel(row);
        AuthTestResult result = authTestResults.get(modelRow);

        // 如果是需要确认的结果（黄色），则让用户选择是漏洞还是安全
        if (result.isNeedsConfirmation()) {
            Object[] options = {"确认为漏洞", "确认为安全", "取消"};
            int choice = JOptionPane.showOptionDialog(mainPanel, "请确认该测试结果的状态：\nURL: " + result.getUrl() + "\n状态码: " + result.getStatusCode(), "确认测试结果", JOptionPane.YES_NO_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE, null, options, options[2]);

            if (choice == 0) { // 确认为漏洞
                result.setVulnerable(true);
                result.setNeedsConfirmation(false);
                log.info("已确认 URL: " + result.getUrl() + " 存在未授权访问漏洞");
            } else if (choice == 1) { // 确认为安全
                result.setVulnerable(false);
                result.setNeedsConfirmation(false);
                log.info("已确认 URL: " + result.getUrl() + " 不存在未授权访问漏洞");
            } else {
                // 取消操作
                return;
            }
            result.setSelected(false);
            // 更新表格
            authTestTableModel.fireTableDataChanged();
        } else {
            JOptionPane.showMessageDialog(mainPanel, "选中的结果不需要确认", "提示", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    /**
     * 导出未授权访问测试结果到CSV文件
     */
    private void exportAuthTestResults() {
        if (authTestResults.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, "没有测试结果可导出！", "错误", JOptionPane.ERROR_MESSAGE);
            log.warn("导出失败：没有测试结果");
            return;
        }

        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setFileFilter(new FileNameExtensionFilter("CSV 文件 (*.csv)", "csv"));
        fileChooser.setSelectedFile(new File("unauthorized_test_results.csv"));

        int result = fileChooser.showSaveDialog(mainPanel);
        if (result == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            String filePath = selectedFile.getAbsolutePath();

            // 确保文件扩展名正确
            if (!filePath.toLowerCase().endsWith(".csv")) {
                filePath += ".csv";
            }

            try {
                ExportResult.exportAuthTestResultsToCSV(filePath, authTestResults);
                JOptionPane.showMessageDialog(mainPanel, "导出成功！", "信息", JOptionPane.INFORMATION_MESSAGE);
                log.info("成功导出 " + authTestResults.size() + " 条未授权测试结果到文件: " + filePath);
            } catch (IOException e) {
                JOptionPane.showMessageDialog(mainPanel, "导出失败：" + e.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
                log.error("导出失败: " + e.getMessage());
            }
        } else {
            log.info("用户取消了文件选择");
        }
    }

    /**
     * 批量确认选中的未授权测试结果
     */
    private void batchConfirmAuthTestResults() {
        List<AuthTestResult> selectedResults = new ArrayList<>();

        // 收集所有选中的需要确认的结果
        for (AuthTestResult result : authTestResults) {
            if (result.isSelected() && result.isNeedsConfirmation()) {
                selectedResults.add(result);
            }
        }

        if (selectedResults.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, "没有选中需要确认的测试结果", "提示", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        // 弹出确认对话框
        Object[] options = {"确认为漏洞", "确认为安全", "取消"};
        int choice = JOptionPane.showOptionDialog(mainPanel, "请确认 " + selectedResults.size() + " 个选中的测试结果状态", "批量确认测试结果", JOptionPane.YES_NO_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE, null, options, options[2]);

        if (choice == 0) { // 确认为漏洞
            for (AuthTestResult result : selectedResults) {
                result.setVulnerable(true);
                result.setNeedsConfirmation(false);
            }
            log.info("已批量确认 " + selectedResults.size() + " 个URL存在未授权访问漏洞");
        } else if (choice == 1) { // 确认为安全
            for (AuthTestResult result : selectedResults) {
                result.setVulnerable(false);
                result.setNeedsConfirmation(false);
            }
            log.info("已批量确认 " + selectedResults.size() + " 个URL不存在未授权访问漏洞");
        } else {
            // 取消操作
            return;
        }

        // 更新表格
        authTestTableModel.fireTableDataChanged();
    }

    /**
     * 清空CSRF测试结果
     */
    private void clearCsrfTestResults() {
        csrfTestResults.clear();
        csrfTestTableModel.fireTableDataChanged();
        csrfRequestViewer.setText("");
        csrfResponseViewer.setText("");
        log.info("已清空CSRF测试结果");
    }

    /**
     * 确认CSRF测试结果
     */
    private void confirmCsrfTestResult() {
        int selectedRow = csrfTestResultsTable.getSelectedRow();
        if (selectedRow < 0) {
            JOptionPane.showMessageDialog(mainPanel, "请先选择一条测试结果！", "错误", JOptionPane.ERROR_MESSAGE);
            return;
        }

        int modelRow = csrfTestResultsTable.convertRowIndexToModel(selectedRow);
        CsrfTestResult result = csrfTestResults.get(modelRow);

        // 如果不需要确认，则直接返回
        if (!result.isNeedsConfirmation()) {
            JOptionPane.showMessageDialog(mainPanel, "该测试结果不需要确认！", "信息", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        // 弹出确认对话框
        String[] options = {"确认存在CSRF漏洞", "确认不存在CSRF漏洞", "取消"};
        int choice = JOptionPane.showOptionDialog(mainPanel, "请确认URL: " + result.getUrl() + " 的CSRF测试结果：", "确认CSRF测试结果", JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE, null, options, options[0]);

        if (choice == 0) { // 确认为漏洞
            result.setVulnerable(true);
            result.setNeedsConfirmation(false);
            log.info("已确认 URL: " + result.getUrl() + " 存在CSRF漏洞");
        } else if (choice == 1) { // 确认为安全
            result.setVulnerable(false);
            result.setNeedsConfirmation(false);
            log.info("已确认 URL: " + result.getUrl() + " 不存在CSRF漏洞");
        } else {
            // 取消操作
            return;
        }
        result.setSelected(false);
        // 更新表格
        csrfTestTableModel.fireTableDataChanged();
    }

    /**
     * 批量确认CSRF测试结果
     */
    private void batchConfirmCsrfTestResults() {
        // 获取选中的测试结果
        List<CsrfTestResult> selectedResults = new ArrayList<>();
        for (CsrfTestResult result : csrfTestResults) {
            if (result.isSelected() && result.isNeedsConfirmation()) {
                selectedResults.add(result);
            }
        }

        if (selectedResults.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, "没有选择需要确认的测试结果！", "错误", JOptionPane.ERROR_MESSAGE);
            return;
        }

        // 弹出确认对话框
        String[] options = {"确认存在CSRF漏洞", "确认不存在CSRF漏洞", "取消"};
        int choice = JOptionPane.showOptionDialog(mainPanel, "请确认 " + selectedResults.size() + " 个选中的测试结果：", "批量确认CSRF测试结果", JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE, null, options, options[0]);

        if (choice == 0) { // 确认为漏洞
            for (CsrfTestResult result : selectedResults) {
                result.setVulnerable(true);
                result.setNeedsConfirmation(false);
            }
            log.info("已批量确认 " + selectedResults.size() + " 个URL存在CSRF漏洞");
        } else if (choice == 1) { // 确认为安全
            for (CsrfTestResult result : selectedResults) {
                result.setVulnerable(false);
                result.setNeedsConfirmation(false);
            }
            log.info("已批量确认 " + selectedResults.size() + " 个URL不存在CSRF漏洞");
        } else {
            // 取消操作
            return;
        }

        // 更新表格
        csrfTestTableModel.fireTableDataChanged();
    }

    /**
     * 导出CSRF测试结果
     */
    private void exportCsrfTestResults() {
        if (csrfTestResults.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, "没有测试结果可导出！", "错误", JOptionPane.ERROR_MESSAGE);
            log.warn("导出失败：没有CSRF测试结果");
            return;
        }

        // 创建文件选择器
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("保存CSRF测试结果");
        fileChooser.setFileFilter(new FileNameExtensionFilter("CSV文件", "csv"));
        fileChooser.setSelectedFile(new File("csrf_test_results.csv"));

        int result = fileChooser.showSaveDialog(mainPanel);
        if (result == JFileChooser.APPROVE_OPTION) {
            try {
                String filePath = fileChooser.getSelectedFile().getAbsolutePath();
                if (!filePath.toLowerCase().endsWith(".csv")) {
                    filePath += ".csv";
                }

                ExportResult.exportCsrfTestResultsToCSV(filePath, csrfTestResults);
                JOptionPane.showMessageDialog(mainPanel, "导出成功！", "信息", JOptionPane.INFORMATION_MESSAGE);
                log.info("成功导出 " + csrfTestResults.size() + " 条CSRF测试结果到文件: " + filePath);
            } catch (IOException e) {
                JOptionPane.showMessageDialog(mainPanel, "导出失败：" + e.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
                log.error("导出失败: " + e.getMessage());
            }
        } else {
            log.info("用户取消了文件选择");
        }
    }

    /**
     * 清空不安全HTTP方法测试结果
     */
    private void clearUnsafeMethodTestResults() {
        unsafeMethodTestResults.clear();
        unsafeMethodTestTableModel.fireTableDataChanged();
        unsafeMethodRequestViewer.setText("");
        unsafeMethodResponseViewer.setText("");
        log.info("已清空不安全HTTP方法测试结果");
    }

    /**
     * 确认不安全HTTP方法测试结果
     */
    private void confirmUnsafeMethodTestResult() {
        int selectedRow = unsafeMethodResultsTable.getSelectedRow();
        if (selectedRow < 0) {
            JOptionPane.showMessageDialog(mainPanel, "请先选择一条测试结果！", "错误", JOptionPane.ERROR_MESSAGE);
            return;
        }

        int modelRow = unsafeMethodResultsTable.convertRowIndexToModel(selectedRow);
        UnsafeMethodTestResult result = unsafeMethodTestResults.get(modelRow);

        // 如果不需要确认，则直接返回
        if (!result.isNeedsConfirmation()) {
            JOptionPane.showMessageDialog(mainPanel, "该测试结果不需要确认！", "信息", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        // 弹出确认对话框
        String[] options = {"确认存在不安全请求漏洞", "确认不存在不安全请求漏洞", "取消"};
        int choice = JOptionPane.showOptionDialog(mainPanel, "请确认URL: " + result.getUrl() + " 的不安全HTTP方法 " + result.getModifiedMethod() + " 测试结果：", "确认不安全HTTP方法测试结果", JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE, null, options, options[0]);

        if (choice == 0) { // 确认为漏洞
            result.setVulnerable(true);
            result.setNeedsConfirmation(false);
            log.info("已确认 URL: " + result.getUrl() + " 存在不安全HTTP方法漏洞: " + result.getModifiedMethod());
        } else if (choice == 1) { // 确认为安全
            result.setVulnerable(false);
            result.setNeedsConfirmation(false);
            log.info("已确认 URL: " + result.getUrl() + " 不存在不安全HTTP方法漏洞: " + result.getModifiedMethod());
        } else {
            // 取消操作
            return;
        }

        // 更新表格
        unsafeMethodTestTableModel.fireTableDataChanged();
    }

    /**
     * 批量确认不安全HTTP方法测试结果
     */
    private void batchConfirmUnsafeMethodTestResults() {
        // 获取选中的测试结果
        List<UnsafeMethodTestResult> selectedResults = new ArrayList<>();
        for (UnsafeMethodTestResult result : unsafeMethodTestResults) {
            if (result.isSelected() && result.isNeedsConfirmation()) {
                selectedResults.add(result);
            }
        }

        if (selectedResults.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, "没有选择需要确认的测试结果！", "错误", JOptionPane.ERROR_MESSAGE);
            return;
        }

        // 弹出确认对话框
        String[] options = {"确认存在不安全请求漏洞", "确认不存在不安全请求漏洞", "取消"};
        int choice = JOptionPane.showOptionDialog(mainPanel, "请确认 " + selectedResults.size() + " 个选中的测试结果：", "批量确认不安全HTTP方法测试结果", JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE, null, options, options[0]);

        if (choice == 0) { // 确认为漏洞
            for (UnsafeMethodTestResult result : selectedResults) {
                result.setVulnerable(true);
                result.setNeedsConfirmation(false);
            }
            log.info("已批量确认 " + selectedResults.size() + " 个URL存在不安全HTTP方法漏洞");
        } else if (choice == 1) { // 确认为安全
            for (UnsafeMethodTestResult result : selectedResults) {
                result.setVulnerable(false);
                result.setNeedsConfirmation(false);
            }
            log.info("已批量确认 " + selectedResults.size() + " 个URL不存在不安全HTTP方法漏洞");
        } else {
            // 取消操作
            return;
        }

        // 更新表格
        unsafeMethodTestTableModel.fireTableDataChanged();
    }

    /**
     * 导出不安全HTTP方法测试结果
     */
    private void exportUnsafeMethodTestResults() {
        if (unsafeMethodTestResults.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, "没有测试结果可导出！", "错误", JOptionPane.ERROR_MESSAGE);
            log.warn("导出失败：没有不安全HTTP方法测试结果");
            return;
        }

        // 创建文件选择器
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("保存不安全HTTP方法测试结果");
        fileChooser.setFileFilter(new FileNameExtensionFilter("CSV文件", "csv"));
        fileChooser.setSelectedFile(new File("unsafe_method_test_results.csv"));

        int result = fileChooser.showSaveDialog(mainPanel);
        if (result == JFileChooser.APPROVE_OPTION) {
            try {
                String filePath = fileChooser.getSelectedFile().getAbsolutePath();
                if (!filePath.toLowerCase().endsWith(".csv")) {
                    filePath += ".csv";
                }
                ExportResult.exportUnsafeMethodTestResultsToCSV(filePath, unsafeMethodTestResults);
                JOptionPane.showMessageDialog(mainPanel, "导出成功！", "信息", JOptionPane.INFORMATION_MESSAGE);
                log.info("成功导出 " + unsafeMethodTestResults.size() + " 条不安全HTTP方法测试结果到文件: " + filePath);
            } catch (IOException e) {
                JOptionPane.showMessageDialog(mainPanel, "导出失败：" + e.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
                log.error("导出失败: " + e.getMessage());
            }
        } else {
            log.info("用户取消了文件选择");
        }
    }

    /**
     * 生成会话字符串
     *
     * @param session 会话对象
     * @return 会话字符串，包含Cookie和Authorization头
     */
    private String getSessionString(TestSession session) {
        StringBuilder sb = new StringBuilder();

        if (session.getCookies() != null && !session.getCookies().trim().isEmpty()) {
            sb.append("Cookie: ").append(session.getCookies()).append("\n");
        }

        if (session.getAuthorization() != null && !session.getAuthorization().trim().isEmpty()) {
            sb.append("Authorization: ").append(session.getAuthorization());
        }
        log.debug("回话字符串:{}", sb.toString());
        return sb.toString();
    }

    /**
     * 导出越权测试结果到CSV文件
     */
    private void exportPrivilegeEscalationResults() {
        if (privilegeEscalationResults.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, "没有测试结果可导出！", "错误", JOptionPane.ERROR_MESSAGE);
            log.warn("导出失败：没有越权测试结果");
            return;
        }

        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setFileFilter(new FileNameExtensionFilter("CSV 文件 (*.csv)", "csv"));
        fileChooser.setSelectedFile(new File("privilege_escalation_results.csv"));

        int result = fileChooser.showSaveDialog(mainPanel);
        if (result == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            String filePath = selectedFile.getAbsolutePath();

            // 确保文件扩展名正确
            if (!filePath.toLowerCase().endsWith(".csv")) {
                filePath += ".csv";
            }

            try {
                ExportResult.exportPrivilegeEscalationResultsToCSV(filePath, privilegeEscalationResults);
                JOptionPane.showMessageDialog(mainPanel, "导出成功！", "信息", JOptionPane.INFORMATION_MESSAGE);
                log.info("成功导出 " + privilegeEscalationResults.size() + " 条越权测试结果到文件: " + filePath);
            } catch (IOException e) {
                JOptionPane.showMessageDialog(mainPanel, "导出失败：" + e.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
                log.error("导出失败: " + e.getMessage());
            }
        } else {
            log.info("用户取消了文件选择");
        }
    }

    private void createPrivilegeEscalationTestPanel() {
        privilegeEscalationPanel = new JPanel(new BorderLayout());

        // 创建测试会话管理面板
        JPanel sessionPanel = new JPanel(new BorderLayout());
        JPanel sessionControlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        // 会话列表模型
        DefaultListModel<TestSession> sessionListModel = new DefaultListModel<>();
        JList<TestSession> sessionList = new JList<>(sessionListModel);
        sessionList.setCellRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
                super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                if (value instanceof TestSession) {
                    TestSession session = (TestSession) value;
                    setText(session.getName() + " (权限级别: " + session.getPrivilegeLevel() + ")");
                }
                return this;
            }
        });

        // 会话控制按钮
        JButton addSessionButton = new JButton("添加会话");
        JButton editSessionButton = new JButton("编辑会话");
        JButton removeSessionButton = new JButton("删除会话");
        JButton importSessionButton = new JButton("导入会话");
        JButton exportSessionButton = new JButton("导出会话");

        // 添加会话按钮事件
        addSessionButton.addActionListener(e -> {
            // 创建会话添加对话框
            JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(mainPanel), "添加会话", true);
            dialog.setLayout(new BorderLayout());

            JPanel formPanel = new JPanel(new GridBagLayout());
            GridBagConstraints gbc = new GridBagConstraints();
            gbc.fill = GridBagConstraints.HORIZONTAL;
            gbc.insets = new Insets(5, 5, 5, 5);

            // 会话名称
            gbc.gridx = 0;
            gbc.gridy = 0;
            formPanel.add(new JLabel("会话名称:"), gbc);

            gbc.gridx = 1;
            JTextField nameField = new JTextField(20);
            formPanel.add(nameField, gbc);

            // Cookie
            gbc.gridx = 0;
            gbc.gridy = 1;
            formPanel.add(new JLabel("Cookie:"), gbc);

            gbc.gridx = 1;
            JTextArea cookieArea = new JTextArea(5, 20);
            JScrollPane cookieScrollPane = new JScrollPane(cookieArea);
            formPanel.add(cookieScrollPane, gbc);

            // Authorization头
            gbc.gridx = 0;
            gbc.gridy = 2;
            formPanel.add(new JLabel("Authorization:"), gbc);

            gbc.gridx = 1;
            JTextField authField = new JTextField(20);
            formPanel.add(authField, gbc);

            // 权限级别
            gbc.gridx = 0;
            gbc.gridy = 3;
            formPanel.add(new JLabel("权限级别:"), gbc);

            gbc.gridx = 1;
            SpinnerNumberModel privilegeModel = new SpinnerNumberModel(1, 0, 10, 1);
            JSpinner privilegeSpinner = new JSpinner(privilegeModel);
            formPanel.add(privilegeSpinner, gbc);

            // 按钮面板
            JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
            JButton saveButton = new JButton("保存");
            JButton cancelButton = new JButton("取消");

            saveButton.addActionListener(saveEvent -> {
                String name = nameField.getText().trim();
                String cookies = cookieArea.getText().trim();
                String authorization = authField.getText().trim();
                int privilegeLevel = (Integer) privilegeSpinner.getValue();

                if (name.isEmpty()) {
                    JOptionPane.showMessageDialog(dialog, "会话名称不能为空", "错误", JOptionPane.ERROR_MESSAGE);
                    return;
                }

                // 创建会话并添加到列表
                TestSession session = new TestSession(name, cookies, authorization, privilegeLevel);
                sessionListModel.addElement(session);
                dialog.dispose();
                log.info("已添加会话: " + name);
            });

            cancelButton.addActionListener(cancelEvent -> dialog.dispose());

            buttonPanel.add(saveButton);
            buttonPanel.add(cancelButton);

            dialog.add(formPanel, BorderLayout.CENTER);
            dialog.add(buttonPanel, BorderLayout.SOUTH);
            dialog.pack();
            dialog.setLocationRelativeTo(mainPanel);
            dialog.setVisible(true);
        });

        // 编辑会话按钮事件
        editSessionButton.addActionListener(e -> {
            TestSession selectedSession = sessionList.getSelectedValue();
            if (selectedSession == null) {
                JOptionPane.showMessageDialog(mainPanel, "请先选择一个会话", "提示", JOptionPane.INFORMATION_MESSAGE);
                return;
            }

            // 创建会话编辑对话框
            JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(mainPanel), "编辑会话", true);
            dialog.setLayout(new BorderLayout());

            JPanel formPanel = new JPanel(new GridBagLayout());
            GridBagConstraints gbc = new GridBagConstraints();
            gbc.fill = GridBagConstraints.HORIZONTAL;
            gbc.insets = new Insets(5, 5, 5, 5);

            // 会话名称
            gbc.gridx = 0;
            gbc.gridy = 0;
            formPanel.add(new JLabel("会话名称:"), gbc);

            gbc.gridx = 1;
            JTextField nameField = new JTextField(selectedSession.getName(), 20);
            formPanel.add(nameField, gbc);

            // Cookie
            gbc.gridx = 0;
            gbc.gridy = 1;
            formPanel.add(new JLabel("Cookie:"), gbc);

            gbc.gridx = 1;
            JTextArea cookieArea = new JTextArea(selectedSession.getCookies(), 5, 20);
            JScrollPane cookieScrollPane = new JScrollPane(cookieArea);
            formPanel.add(cookieScrollPane, gbc);

            // Authorization头
            gbc.gridx = 0;
            gbc.gridy = 2;
            formPanel.add(new JLabel("Authorization:"), gbc);

            gbc.gridx = 1;
            JTextField authField = new JTextField(selectedSession.getAuthorization(), 20);
            formPanel.add(authField, gbc);

            // 权限级别
            gbc.gridx = 0;
            gbc.gridy = 3;
            formPanel.add(new JLabel("权限级别:"), gbc);

            gbc.gridx = 1;
            SpinnerNumberModel privilegeModel = new SpinnerNumberModel(selectedSession.getPrivilegeLevel(), 0, 10, 1);
            JSpinner privilegeSpinner = new JSpinner(privilegeModel);
            formPanel.add(privilegeSpinner, gbc);

            // 按钮面板
            JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
            JButton saveButton = new JButton("保存");
            JButton cancelButton = new JButton("取消");

            saveButton.addActionListener(saveEvent -> {
                String name = nameField.getText().trim();
                String cookies = cookieArea.getText().trim();
                String authorization = authField.getText().trim();
                int privilegeLevel = (Integer) privilegeSpinner.getValue();

                if (name.isEmpty()) {
                    JOptionPane.showMessageDialog(dialog, "会话名称不能为空", "错误", JOptionPane.ERROR_MESSAGE);
                    return;
                }

                // 更新会话信息
                int selectedIndex = sessionList.getSelectedIndex();
                TestSession updatedSession = new TestSession(name, cookies, authorization, privilegeLevel);
                sessionListModel.setElementAt(updatedSession, selectedIndex);
                dialog.dispose();
                log.info("已更新会话: " + name);
            });

            cancelButton.addActionListener(cancelEvent -> dialog.dispose());

            buttonPanel.add(saveButton);
            buttonPanel.add(cancelButton);

            dialog.add(formPanel, BorderLayout.CENTER);
            dialog.add(buttonPanel, BorderLayout.SOUTH);
            dialog.pack();
            dialog.setLocationRelativeTo(mainPanel);
            dialog.setVisible(true);
        });

        // 删除会话按钮事件
        removeSessionButton.addActionListener(e -> {
            int selectedIndex = sessionList.getSelectedIndex();
            if (selectedIndex == -1) {
                JOptionPane.showMessageDialog(mainPanel, "请先选择一个会话", "提示", JOptionPane.INFORMATION_MESSAGE);
                return;
            }

            TestSession selectedSession = sessionList.getSelectedValue();
            int confirm = JOptionPane.showConfirmDialog(mainPanel, "确定要删除会话 \"" + selectedSession.getName() + "\" 吗？", "确认删除", JOptionPane.YES_NO_OPTION);

            if (confirm == JOptionPane.YES_OPTION) {
                sessionListModel.remove(selectedIndex);
                log.info("已删除会话: " + selectedSession.getName());
            }
        });

        // 导入会话按钮事件（暂不实现）
        importSessionButton.addActionListener(e -> {
            JOptionPane.showMessageDialog(mainPanel, "此功能暂未实现", "提示", JOptionPane.INFORMATION_MESSAGE);
        });

        // 导出会话按钮事件（暂不实现）
        exportSessionButton.addActionListener(e -> {
            JOptionPane.showMessageDialog(mainPanel, "此功能暂未实现", "提示", JOptionPane.INFORMATION_MESSAGE);
        });

        // 添加按钮到控制面板
        sessionControlPanel.add(addSessionButton);
        sessionControlPanel.add(editSessionButton);
        sessionControlPanel.add(removeSessionButton);
        sessionControlPanel.add(importSessionButton);
        sessionControlPanel.add(exportSessionButton);

        // 添加会话列表到面板
        sessionPanel.add(sessionControlPanel, BorderLayout.NORTH);
        sessionPanel.add(new JScrollPane(sessionList), BorderLayout.CENTER);

        // 创建测试配置面板
        JPanel configPanel = new JPanel(new GridBagLayout());
        GridBagConstraints configGbc = new GridBagConstraints();
        configGbc.fill = GridBagConstraints.HORIZONTAL;
        configGbc.insets = new Insets(5, 5, 5, 5);

        // 测试类型
        configGbc.gridx = 0;
        configGbc.gridy = 0;
        configPanel.add(new JLabel("测试类型:"), configGbc);

        configGbc.gridx = 1;
        String[] testTypes = {"水平越权", "垂直越权", "两者都测试"};
        JComboBox<String> testTypeComboBox = new JComboBox<>(testTypes);
        configPanel.add(testTypeComboBox, configGbc);

        // 会话替换说明
        configGbc.gridx = 0;
        configGbc.gridy = 1;
        configGbc.gridwidth = 2;
        JLabel sessionReplaceLabel = new JLabel("越权测试仅通过替换会话(Cookie/Authorization)进行，不需要修改请求参数");
        configPanel.add(sessionReplaceLabel, configGbc);

        // URL参数过滤选项
        configGbc.gridx = 0;
        configGbc.gridy = 2;
        configGbc.gridwidth = 2;
        JCheckBox urlFilterCheckBox = new JCheckBox("开启URL参数过滤去重（移除?后参数）", false);
        configPanel.add(urlFilterCheckBox, configGbc);

        // 安全关键词配置
        configGbc.gridx = 0;
        configGbc.gridy = 3;
        configGbc.gridwidth = 1;
        configPanel.add(new JLabel("安全关键词:"), configGbc);

        configGbc.gridx = 1;
        JTextField safeKeywordsField = new JTextField("", 20);
        configPanel.add(safeKeywordsField, configGbc);

        // 安全关键词提示
        configGbc.gridx = 0;
        configGbc.gridy = 4;
        configGbc.gridwidth = 2;
        JLabel safeKeywordsHint = new JLabel("多个关键词用逗号分隔，响应中含有关键词则判定为安全");
        configPanel.add(safeKeywordsHint, configGbc);

        // 会话提示
        configGbc.gridx = 0;
        configGbc.gridy = 5;
        configGbc.gridwidth = 2;
        JLabel sessionInfoLabel = new JLabel("请在左侧添加不同权限级别的会话");
        configPanel.add(sessionInfoLabel, configGbc);

        // 启用会话自动探测
        configGbc.gridx = 0;
        configGbc.gridy = 6;
        configGbc.gridwidth = 1;
        configPanel.add(new JLabel("会话自动探测:"), configGbc);

        configGbc.gridx = 1;
        JCheckBox autoSessionCheckBox = new JCheckBox("启用会话自动探测");
        autoSessionCheckBox.setSelected(true);
        configPanel.add(autoSessionCheckBox, configGbc);

        // 测试按钮
        configGbc.gridx = 0;
        configGbc.gridy = 7;
        configGbc.gridwidth = 2;
        JButton testButton = new JButton("开始测试");
        testButton.addActionListener(e -> {
            // 获取选中的请求
            final List<RequestResponseInfo> selectedData = new ArrayList<>();
            synchronized (capturedData) {
                for (RequestResponseInfo info : capturedData) {
                    if (info.isSelected()) {
                        selectedData.add(info);
                    }
                }
            }

            if (selectedData.isEmpty()) {
                // 如果没有选中的请求，显示提示信息
                JOptionPane.showMessageDialog(mainPanel, "请在「请求列表」标签页中选择要测试的请求，然后点击「测试越权」按钮，或直接在这里添加会话配置并开始测试。", "提示", JOptionPane.INFORMATION_MESSAGE);
                return; // 没有请求无法进行测试
            }

            // 获取会话列表
            if (sessionListModel.isEmpty() || sessionListModel.size() < 2) {
                JOptionPane.showMessageDialog(mainPanel, "请至少添加两个不同的会话！", "错误", JOptionPane.ERROR_MESSAGE);
                log.warn("越权测试失败：会话数量不足");
                return;
            }

            // 获取配置
            String testTypeStr = (String) testTypeComboBox.getSelectedItem();
            boolean enableUrlFilter = urlFilterCheckBox.isSelected();

            // 获取安全关键词
            safeKeywords.clear();
            String safeKeywordsText = safeKeywordsField.getText().trim();
            if (!safeKeywordsText.isEmpty()) {
                for (String keyword : safeKeywordsText.split(",")) {
                    safeKeywords.add(keyword.trim().toLowerCase());
                }
            }
            //更新安全关键词
            vulnEngine.setGeneralSafeKeywords(safeKeywords);

            // 将会话列表转换为ArrayList
            List<TestSession> sessions = new ArrayList<>();
            for (int i = 0; i < sessionListModel.size(); i++) {
                sessions.add(sessionListModel.getElementAt(i));
            }

            // 转换测试类型为内部使用的代码
            String testType;
            if ("水平越权".equals(testTypeStr)) {
                testType = "horizontal";
            } else if ("垂直越权".equals(testTypeStr)) {
                testType = "vertical";
            } else {
                // 两者都测试 - 默认为水平越权
                testType = "horizontal";
            }

            // 清空现有结果
            privilegeEscalationResults.clear();
            privilegeEscalationTableModel.fireTableDataChanged();

            // 调用执行越权测试的方法 - 仅进行会话替换测试
            performPrivilegeEscalationTest(selectedData, sessions, testType, null, false, enableUrlFilter);
        });
        configPanel.add(testButton, configGbc);

        // 创建会话和配置面板的组合
        JPanel topPanel = new JPanel(new GridLayout(1, 2));
        topPanel.add(sessionPanel);
        topPanel.add(configPanel);

        // 创建表格模型
        privilegeEscalationTableModel = new PrivilegeEscalationTableModel(privilegeEscalationResults);
        JTable privilegeEscalationResultsTable = new JTable(privilegeEscalationTableModel);

        // 设置表格列宽
        privilegeEscalationResultsTable.getColumnModel().getColumn(0).setMaxWidth(50); // 选择列
        privilegeEscalationResultsTable.getColumnModel().getColumn(1).setMaxWidth(50); // 序号列

        // 添加表格排序器
        TableRowSorter<PrivilegeEscalationTableModel> sorter = new TableRowSorter<>(privilegeEscalationTableModel);
        privilegeEscalationResultsTable.setRowSorter(sorter);

        // 设置表格整行背景色渲染器
        privilegeEscalationResultsTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

                if (!isSelected) {
                    int modelRow = table.convertRowIndexToModel(row);
                    if (modelRow < privilegeEscalationResults.size()) {
                        PrivilegeEscalationResult result = privilegeEscalationResults.get(modelRow);
                        if (result.isVulnerable()) {
                            c.setBackground(new Color(255, 200, 200)); // 浅红色背景表示漏洞
                        } else if (result.isNeedsConfirmation()) {
                            c.setBackground(new Color(255, 235, 200)); // 浅橙色背景表示需要确认
                        } else {
                            c.setBackground(new Color(220, 255, 220)); // 浅绿色背景表示安全
                        }
                    } else {
                        c.setBackground(table.getBackground());
                    }
                }

                return c;
            }
        });

        // 创建结果表格控制面板
        JPanel resultControlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton clearResultsButton = new JButton("清空结果");
        JButton exportResultsButton = new JButton("导出结果");
        JButton confirmButton = new JButton("确认漏洞");
        JButton batchConfirmButton = new JButton("批量确认");
        JButton selectAllButton = new JButton("全选");
        JButton deselectAllButton = new JButton("取消全选");

        // 添加按钮事件处理（暂不实现）
        clearResultsButton.addActionListener(e -> {
            privilegeEscalationResults.clear();
            privilegeEscalationTableModel.fireTableDataChanged();
            privilegeEscalationOriginalRequestViewer.setText("");
            privilegeEscalationOriginalResponseViewer.setText("");
            privilegeEscalationModifiedRequestViewer.setText("");
            privilegeEscalationModifiedResponseViewer.setText("");
            log.info("已清空越权测试结果");
        });

        exportResultsButton.addActionListener(e -> {
            exportPrivilegeEscalationResults();
        });

        confirmButton.addActionListener(e -> {
            // 手工判定功能
            int row = privilegeEscalationResultsTable.getSelectedRow();
            if (row == -1) {
                JOptionPane.showMessageDialog(mainPanel, "请先选择一个测试结果", "提示", JOptionPane.INFORMATION_MESSAGE);
                return;
            }

            int modelRow = privilegeEscalationResultsTable.convertRowIndexToModel(row);
            PrivilegeEscalationResult result = privilegeEscalationResults.get(modelRow);

            // 创建判定对话框
            JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(mainPanel), "手工判定结果", true);
            dialog.setLayout(new BorderLayout());

            JPanel formPanel = new JPanel(new GridBagLayout());
            GridBagConstraints gbc = new GridBagConstraints();
            gbc.fill = GridBagConstraints.HORIZONTAL;
            gbc.insets = new Insets(5, 5, 5, 5);

            // URL信息
            gbc.gridx = 0;
            gbc.gridy = 0;
            formPanel.add(new JLabel("URL:"), gbc);

            gbc.gridx = 1;
            JLabel urlLabel = new JLabel(result.getUrl());
            formPanel.add(urlLabel, gbc);

            // 判定选择
            gbc.gridx = 0;
            gbc.gridy = 1;
            formPanel.add(new JLabel("判定结果:"), gbc);

            gbc.gridx = 1;
            String[] judgmentOptions = {"存在漏洞", "不存在漏洞", "需要进一步确认"};
            JComboBox<String> judgmentComboBox = new JComboBox<>(judgmentOptions);
            if (result.isVulnerable()) {
                judgmentComboBox.setSelectedItem("存在漏洞");
            } else if (result.isNeedsConfirmation()) {
                judgmentComboBox.setSelectedItem("需要进一步确认");
            } else {
                judgmentComboBox.setSelectedItem("不存在漏洞");
            }
            formPanel.add(judgmentComboBox, gbc);

            // 备注
            gbc.gridx = 0;
            gbc.gridy = 2;
            formPanel.add(new JLabel("备注:"), gbc);

            gbc.gridx = 1;
            JTextField noteField = new JTextField(20);
            formPanel.add(noteField, gbc);

            // 按钮面板
            JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
            JButton saveButton = new JButton("保存");
            JButton cancelButton = new JButton("取消");

            saveButton.addActionListener(saveEvent -> {
                String judgment = (String) judgmentComboBox.getSelectedItem();

                if ("存在漏洞".equals(judgment)) {
                    result.setVulnerable(true);
                    result.setNeedsConfirmation(false);
                } else if ("不存在漏洞".equals(judgment)) {
                    result.setVulnerable(false);
                    result.setNeedsConfirmation(false);
                } else {
                    result.setVulnerable(false);
                    result.setNeedsConfirmation(true);
                }

                privilegeEscalationTableModel.fireTableRowsUpdated(modelRow, modelRow);
                dialog.dispose();
                log.info("已手工判定 URL: " + result.getUrl() + ", 结果: " + judgment);
            });

            cancelButton.addActionListener(cancelEvent -> dialog.dispose());

            buttonPanel.add(saveButton);
            buttonPanel.add(cancelButton);

            dialog.add(formPanel, BorderLayout.CENTER);
            dialog.add(buttonPanel, BorderLayout.SOUTH);
            dialog.pack();
            dialog.setLocationRelativeTo(mainPanel);
            dialog.setVisible(true);
        });

        batchConfirmButton.addActionListener(e -> {
            // 批量确认功能
            boolean hasSelected = false;
            for (PrivilegeEscalationResult result : privilegeEscalationResults) {
                if (result.isSelected()) {
                    hasSelected = true;
                    break;
                }
            }

            if (!hasSelected) {
                JOptionPane.showMessageDialog(mainPanel, "请先选择要批量判定的结果", "提示", JOptionPane.INFORMATION_MESSAGE);
                return;
            }

            // 创建批量判定对话框
            JDialog dialog = new JDialog((Frame) SwingUtilities.getWindowAncestor(mainPanel), "批量判定结果", true);
            dialog.setLayout(new BorderLayout());

            JPanel formPanel = new JPanel(new GridBagLayout());
            GridBagConstraints gbc = new GridBagConstraints();
            gbc.fill = GridBagConstraints.HORIZONTAL;
            gbc.insets = new Insets(5, 5, 5, 5);

            // 判定选择
            gbc.gridx = 0;
            gbc.gridy = 0;
            formPanel.add(new JLabel("批量判定为:"), gbc);

            gbc.gridx = 1;
            String[] judgmentOptions = {"存在漏洞", "不存在漏洞", "需要进一步确认"};
            JComboBox<String> judgmentComboBox = new JComboBox<>(judgmentOptions);
            formPanel.add(judgmentComboBox, gbc);

            // 按钮面板
            JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
            JButton saveButton = new JButton("保存");
            JButton cancelButton = new JButton("取消");

            saveButton.addActionListener(saveEvent -> {
                String judgment = (String) judgmentComboBox.getSelectedItem();
                int count = 0;

                for (PrivilegeEscalationResult result : privilegeEscalationResults) {
                    if (result.isSelected()) {
                        if ("存在漏洞".equals(judgment)) {
                            result.setVulnerable(true);
                            result.setNeedsConfirmation(false);
                        } else if ("不存在漏洞".equals(judgment)) {
                            result.setVulnerable(false);
                            result.setNeedsConfirmation(false);
                        } else {
                            result.setVulnerable(false);
                            result.setNeedsConfirmation(true);
                        }
                        count++;
                    }
                }

                privilegeEscalationTableModel.fireTableDataChanged();
                dialog.dispose();
                log.info("已批量判定 " + count + " 条结果为: " + judgment);
            });

            cancelButton.addActionListener(cancelEvent -> dialog.dispose());

            buttonPanel.add(saveButton);
            buttonPanel.add(cancelButton);

            dialog.add(formPanel, BorderLayout.CENTER);
            dialog.add(buttonPanel, BorderLayout.SOUTH);
            dialog.pack();
            dialog.setLocationRelativeTo(mainPanel);
            dialog.setVisible(true);
        });

        selectAllButton.addActionListener(e -> {
            for (PrivilegeEscalationResult result : privilegeEscalationResults) {
                result.setSelected(true);
            }
            privilegeEscalationTableModel.fireTableDataChanged();
            log.info("已全选 " + privilegeEscalationResults.size() + " 条越权测试结果");
        });

        deselectAllButton.addActionListener(e -> {
            for (PrivilegeEscalationResult result : privilegeEscalationResults) {
                result.setSelected(false);
            }
            privilegeEscalationTableModel.fireTableDataChanged();
            log.info("已取消全选 " + privilegeEscalationResults.size() + " 条越权测试结果");
        });

        // 添加按钮到控制面板
        resultControlPanel.add(clearResultsButton);
        resultControlPanel.add(exportResultsButton);
        resultControlPanel.add(confirmButton);
        resultControlPanel.add(batchConfirmButton);
        resultControlPanel.add(selectAllButton);
        resultControlPanel.add(deselectAllButton);

        // 创建请求和响应查看器
        privilegeEscalationOriginalRequestViewer = new JTextArea();
        privilegeEscalationOriginalRequestViewer.setEditable(false);
        JScrollPane originalRequestScrollPane = new JScrollPane(privilegeEscalationOriginalRequestViewer);

        privilegeEscalationOriginalResponseViewer = new JTextArea();
        privilegeEscalationOriginalResponseViewer.setEditable(false);
        JScrollPane originalResponseScrollPane = new JScrollPane(privilegeEscalationOriginalResponseViewer);

        privilegeEscalationModifiedRequestViewer = new JTextArea();
        privilegeEscalationModifiedRequestViewer.setEditable(false);
        JScrollPane modifiedRequestScrollPane = new JScrollPane(privilegeEscalationModifiedRequestViewer);

        privilegeEscalationModifiedResponseViewer = new JTextArea();
        privilegeEscalationModifiedResponseViewer.setEditable(false);
        JScrollPane modifiedResponseScrollPane = new JScrollPane(privilegeEscalationModifiedResponseViewer);

        // 创建原始请求/响应分割面板
        JSplitPane originalSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, originalRequestScrollPane, originalResponseScrollPane);
        originalSplitPane.setResizeWeight(0.5);

        // 创建修改后请求/响应分割面板
        JSplitPane modifiedSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, modifiedRequestScrollPane, modifiedResponseScrollPane);
        modifiedSplitPane.setResizeWeight(0.5);

        // 创建查看器标签页
        JTabbedPane viewerTabbedPane = new JTabbedPane();
        viewerTabbedPane.addTab("原始请求/响应", originalSplitPane);
        viewerTabbedPane.addTab("修改后请求/响应", modifiedSplitPane);

        // 添加双击事件，显示请求和响应详情
        privilegeEscalationResultsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int row = privilegeEscalationResultsTable.convertRowIndexToModel(privilegeEscalationResultsTable.getSelectedRow());
                    if (row >= 0 && row < privilegeEscalationResults.size()) {
                        PrivilegeEscalationResult result = privilegeEscalationResults.get(row);

                        // 显示原始请求和响应
                        privilegeEscalationOriginalRequestViewer.setText(result.getOriginalRequestHeaders() + result.getOriginalRequestBody());
                        privilegeEscalationOriginalResponseViewer.setText(result.getOriginalResponseHeaders() + result.getOriginalResponseBody());

                        // 显示修改后请求和响应
                        privilegeEscalationModifiedRequestViewer.setText(result.getModifiedRequestHeaders() + result.getModifiedRequestBody());
                        privilegeEscalationModifiedResponseViewer.setText(result.getModifiedResponseHeaders() + result.getModifiedResponseBody());
                    }
                }
            }
        });

        // 创建分割面板
        JSplitPane resultSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(privilegeEscalationResultsTable), viewerTabbedPane);
        resultSplitPane.setResizeWeight(0.5);

        // 创建整体布局
        privilegeEscalationPanel.add(topPanel, BorderLayout.NORTH);
        privilegeEscalationPanel.add(resultControlPanel, BorderLayout.SOUTH);
        privilegeEscalationPanel.add(resultSplitPane, BorderLayout.CENTER);
    }


    /**
     * 导出请求为sqlmap格式（每个请求一个txt文件）
     */
    private void exportSqlmapFormat() {
        List<RequestResponseInfo> selectedData = new ArrayList<>();
        synchronized (capturedData) {
            for (RequestResponseInfo info : capturedData) {
                if (info.isSelected()) {
                    selectedData.add(info);
                }
            }
        }

        if (selectedData.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, "没有选择任何数据！", "错误", JOptionPane.ERROR_MESSAGE);
            log.warn("导出失败：没有选择任何数据");
            return;
        }

        // 选择保存目录
        JFileChooser dirChooser = new JFileChooser();
        dirChooser.setDialogTitle("选择保存目录");
        dirChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);

        int result = dirChooser.showSaveDialog(mainPanel);
        if (result == JFileChooser.APPROVE_OPTION) {
            File selectedDir = dirChooser.getSelectedFile();
            String dirPath = selectedDir.getAbsolutePath();

            // 确保目录存在
            if (!selectedDir.exists()) {
                selectedDir.mkdirs();
            }

            // 检查目录是否为空
            File[] files = selectedDir.listFiles();
            if (files != null && files.length > 0) {
                int confirm = JOptionPane.showConfirmDialog(mainPanel, "所选目录不为空，可能会覆盖现有文件。是否继续？", "确认", JOptionPane.YES_NO_OPTION);
                if (confirm != JOptionPane.YES_OPTION) {
                    log.info("用户取消了导出，因为目录不为空");
                    return;
                }
            }

            // 显示进度条
            progressBar.setVisible(true);
            progressBar.setValue(0);
            progressBar.setMaximum(selectedData.size());
            statusLabel.setText("正在导出请求...");

            // 使用新线程进行导出，避免阻塞UI
            new Thread(() -> {
                int successCount = 0;

                try {
                    for (int i = 0; i < selectedData.size(); i++) {
                        RequestResponseInfo info = selectedData.get(i);

                        // 更新进度条
                        final int currentIndex = i;
                        SwingUtilities.invokeLater(() -> {
                            progressBar.setValue(currentIndex + 1);
                            statusLabel.setText("正在导出 " + (currentIndex + 1) + "/" + selectedData.size() + " 个请求...");
                        });

                        // 生成文件名，使用递增的数字从1开始
                        String fileName = (i + 1) + ".txt";
                        File outputFile = new File(dirPath, fileName);

                        try (FileWriter writer = new FileWriter(outputFile)) {
                            // 确保请求头按照HTTP标准格式化，每行一个头部字段
                            String requestHeaders = info.getRequestHeaders();

                            // 检查请求头是否已经包含正确的换行符
                            if (!requestHeaders.contains("\r\n")) {
                                // 使用UrlUtil工具类进行格式化
                                requestHeaders = UrlUtil.formatHttpHeaders(requestHeaders);
                            }

                            // 写入格式化后的请求头
                            writer.write(requestHeaders);

                            // 确保请求头和请求体之间有一个空行
                            if (!requestHeaders.endsWith("\r\n\r\n")) {
                                if (requestHeaders.endsWith("\r\n")) {
                                    writer.write("\r\n");
                                } else {
                                    writer.write("\r\n\r\n");
                                }
                            }

                            // 写入请求体
                            if (info.getRequestBody() != null && !info.getRequestBody().isEmpty()) {
                                writer.write(info.getRequestBody());
                            }
                            successCount++;
                        } catch (IOException e) {
                            log.error("导出请求 " + info.getUrl() + " 失败: " + e.getMessage());
                        }
                    }

                    // 导出完成后更新UI
                    final int finalSuccessCount = successCount;
                    SwingUtilities.invokeLater(() -> {
                        progressBar.setVisible(false);
                        statusLabel.setText("就绪");
                        JOptionPane.showMessageDialog(mainPanel, "成功导出 " + finalSuccessCount + "/" + selectedData.size() + " 个请求到目录: " + dirPath, "导出完成", JOptionPane.INFORMATION_MESSAGE);
                    });
                    log.info("成功导出 {} 个请求到目录: {}", finalSuccessCount, dirPath);

                } catch (Exception e) {
                    SwingUtilities.invokeLater(() -> {
                        progressBar.setVisible(false);
                        statusLabel.setText("导出失败");
                        JOptionPane.showMessageDialog(mainPanel, "导出失败: " + e.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
                    });
                    log.error("导出失败", e);
                }
            }).start();
        } else {
            log.info("用户取消了目录选择");
        }
    }
} 