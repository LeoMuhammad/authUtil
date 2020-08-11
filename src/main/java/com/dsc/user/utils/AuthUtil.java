package com.dsc.user.utils;

import com.dsc.user.entity.User;
import io.jsonwebtoken.*;
import org.apache.commons.lang.StringUtils;


/**
 * @author jinzhiwang
 */
public class AuthUtil {
    /**
     * Authorization认证开头是"bearer "
     */
    private static final String BEARER = "Bearer ";

    public static Jws<Claims> getJwt(String jwtToken, String key) {
        if (jwtToken.startsWith(BEARER)) {
            jwtToken = StringUtils.substring(jwtToken, BEARER.length());
        }
        return Jwts.parser()  //得到DefaultJwtParser
                .setSigningKey(key.getBytes()) //设置签名的秘钥
                .parseClaimsJws(jwtToken);
    }

    public static User checkToken(String authentication, String key) {
        // 如果请求未携带token信息, 直接权限
        if (StringUtils.isBlank(authentication) || !authentication.startsWith(BEARER)) {
            return null;
        }
        //token是否有效，在网关进行校验，无效/过期等
        if (invalidJwtAccessToken(authentication, key)) {
            return null;
        }
        return new User((String) getJwt(authentication, key).getBody().get("user_name"));
    }

    public static boolean invalidJwtAccessToken(String authentication, String key) {
        // 是否无效true表示无效
        boolean invalid = Boolean.TRUE;
        try {
            getJwt(authentication, key);
            invalid = Boolean.FALSE;
        } catch (SignatureException | ExpiredJwtException | MalformedJwtException ex) {
//            log.error("user token error :{}", ex.getMessage());
        }
        return invalid;
    }
}
