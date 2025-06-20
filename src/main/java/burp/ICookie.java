package burp;

import java.util.Date;

/**
 * 此接口用于HTTP Cookie
 */
public interface ICookie
{
    /**
     * 获取Cookie名称
     * 
     * @return Cookie名称
     */
    String getName();
    
    /**
     * 获取Cookie值
     * 
     * @return Cookie值
     */
    String getValue();
    
    /**
     * 获取Cookie的域
     * 
     * @return Cookie的域
     */
    String getDomain();
    
    /**
     * 获取Cookie的路径
     * 
     * @return Cookie的路径
     */
    String getPath();
    
    /**
     * 获取Cookie的过期时间
     * 
     * @return Cookie的过期时间
     */
    Date getExpiration();
    
    /**
     * 检查Cookie是否为会话Cookie
     * 
     * @return 如果是会话Cookie则返回true
     */
    boolean isSession();
    
    /**
     * 检查Cookie是否为安全Cookie
     * 
     * @return 如果是安全Cookie则返回true
     */
    boolean isSecure();
    
    /**
     * 检查Cookie是否设置了HttpOnly标志
     * 
     * @return 如果设置了HttpOnly标志则返回true
     */
    boolean isHttpOnly();
} 