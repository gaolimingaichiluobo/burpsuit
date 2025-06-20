package burp;

/**
 * 此接口用于HTTP请求中的参数
 */
public interface IParameter
{
    // 参数类型常量
    byte PARAM_URL = 0;
    byte PARAM_BODY = 1;
    byte PARAM_COOKIE = 2;
    byte PARAM_XML = 3;
    byte PARAM_XML_ATTR = 4;
    byte PARAM_MULTIPART_ATTR = 5;
    byte PARAM_JSON = 6;
    
    /**
     * 获取参数类型
     * 
     * @return 参数类型，使用上面定义的常量
     */
    byte getType();
    
    /**
     * 获取参数名称
     * 
     * @return 参数名称
     */
    String getName();
    
    /**
     * 获取参数值
     * 
     * @return 参数值
     */
    String getValue();
    
    /**
     * 获取参数名称的起始偏移量
     * 
     * @return 参数名称的起始偏移量
     */
    int getNameStart();
    
    /**
     * 获取参数名称的结束偏移量
     * 
     * @return 参数名称的结束偏移量
     */
    int getNameEnd();
    
    /**
     * 获取参数值的起始偏移量
     * 
     * @return 参数值的起始偏移量
     */
    int getValueStart();
    
    /**
     * 获取参数值的结束偏移量
     * 
     * @return 参数值的结束偏移量
     */
    int getValueEnd();
} 