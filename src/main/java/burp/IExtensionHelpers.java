package burp;

import java.net.URL;
import java.util.List;

/**
 * 此接口包含许多帮助方法，供扩展使用
 */
public interface IExtensionHelpers
{
    /**
     * 分析HTTP请求
     * 
     * @param request 完整的HTTP请求
     * @return 请求信息对象
     */
    IRequestInfo analyzeRequest(byte[] request);
    
    /**
     * 分析HTTP请求
     * 
     * @param httpService HTTP服务信息
     * @param request 完整的HTTP请求
     * @return 请求信息对象
     */
    IRequestInfo analyzeRequest(IHttpRequestResponse requestResponse);
    
    /**
     * 分析HTTP响应
     * 
     * @param response 完整的HTTP响应
     * @return 响应信息对象
     */
    IResponseInfo analyzeResponse(byte[] response);
    
    /**
     * 使用指定的HTTP头和消息体构建HTTP消息
     * 
     * @param headers HTTP头列表
     * @param body 消息体
     * @return 完整的HTTP消息
     */
    byte[] buildHttpMessage(List<String> headers, byte[] body);
    
    /**
     * 创建一个HTTP请求，使用指定的方法、URL和HTTP版本
     * 
     * @param url 请求URL
     * @return 一个新的HTTP请求
     */
    byte[] buildHttpRequest(URL url);
    
    /**
     * 添加参数到HTTP请求
     * 
     * @param request 原始HTTP请求
     * @param parameter 要添加的参数
     * @return 添加参数后的HTTP请求
     */
    byte[] addParameter(byte[] request, IParameter parameter);
    
    /**
     * 从HTTP请求中删除指定参数
     * 
     * @param request 原始HTTP请求
     * @param parameter 要删除的参数
     * @return 删除参数后的HTTP请求
     */
    byte[] removeParameter(byte[] request, IParameter parameter);
    
    /**
     * 更新HTTP请求中的指定参数
     * 
     * @param request 原始HTTP请求
     * @param parameter 包含更新值的参数
     * @return 更新参数后的HTTP请求
     */
    byte[] updateParameter(byte[] request, IParameter parameter);
    
    /**
     * 从HTTP请求或响应中提取参数
     * 
     * @param request HTTP请求或响应
     * @return 参数列表
     */
    List<IParameter> getRequestParameters(byte[] request);
    
    /**
     * 从URL中提取参数
     * 
     * @param url 要分析的URL
     * @return 参数列表
     */
    List<IParameter> getUrlParameters(String url);
    
    /**
     * 对字符串进行Base64编码
     * 
     * @param input 要编码的字符串
     * @return 编码后的字符串
     */
    String base64Encode(String input);
    
    /**
     * 对字符串进行Base64编码
     * 
     * @param input 要编码的数据
     * @return 编码后的字符串
     */
    String base64Encode(byte[] input);
    
    /**
     * 对Base64编码的字符串进行解码
     * 
     * @param input 要解码的字符串
     * @return 解码后的字符串
     */
    byte[] base64Decode(String input);
    
    /**
     * 对字符串进行URL编码
     * 
     * @param input 要编码的字符串
     * @return 编码后的字符串
     */
    String urlEncode(String input);
    
    /**
     * 对URL编码的字符串进行解码
     * 
     * @param input 要解码的字符串
     * @return 解码后的字符串
     */
    String urlDecode(String input);
    
    /**
     * 创建一个HTTP参数
     * 
     * @param name 参数名
     * @param value 参数值
     * @param type 参数类型
     * @return 新创建的参数
     */
    IParameter buildParameter(String name, String value, byte type);
    
    /**
     * 将原始数据转换为十六进制格式
     * 
     * @param data 要转换的数据
     * @return 十六进制格式的字符串
     */
    String bytesToHex(byte[] data);
    
    /**
     * 将十六进制字符串转换为原始数据
     * 
     * @param hex 十六进制字符串
     * @return 转换后的数据
     */
    byte[] hexToBytes(String hex);
    
    /**
     * 对字符串进行MD5哈希
     * 
     * @param input 要哈希的字符串
     * @return 哈希结果
     */
    byte[] stringToBytes(String input);
    
    /**
     * 将字节数组转换为字符串
     * 
     * @param input 字节数组
     * @return 转换后的字符串
     */
    String bytesToString(byte[] input);
} 