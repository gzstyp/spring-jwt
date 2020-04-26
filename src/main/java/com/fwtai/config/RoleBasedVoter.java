package com.fwtai.config;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.FilterInvocation;

import java.util.Collection;

/**
 * 实现动态配置url权限
*/
public class RoleBasedVoter implements AccessDecisionVoter<Object>{

    //将两个supports()都设置成true
    @Override
    public boolean supports(final ConfigAttribute attribute){
        return true;
    }

    @Override
    public int vote(final Authentication authentication,final Object object,final Collection<ConfigAttribute> attributes){
        if(authentication == null){
            return ACCESS_DENIED;
        }
        int result = ACCESS_ABSTAIN;
        final Collection<? extends GrantedAuthority> authorities = extractAuthorities(authentication);
        for(final ConfigAttribute attribute : attributes){
            if(attribute.getAttribute() == null){
                continue;
            }
            if(this.supports(attribute)){
                result = ACCESS_DENIED;
                // Attempt to find a matching granted authority(试图找到匹配的授权)
                for(GrantedAuthority authority : authorities){
                    if(attribute.getAttribute().equals(authority.getAuthority())){
                        return ACCESS_GRANTED;
                    }
                }
            }
        }
        final FilterInvocation fi = (FilterInvocation) object;
        final String userName = (String)authentication.getPrincipal();
        final String url = fi.getRequestUrl();//url就是请求的url 这里扩展空间就大了，可以从DB动态加载，然后判断URL的ConfigAttribute就可以了。
        String httpMethod = fi.getRequest().getMethod();
        return result;
    }

    protected Collection<? extends GrantedAuthority> extractAuthorities(final Authentication authentication){
        return authentication.getAuthorities();
    }

    //将两个supports()都设置成true
    @Override
    public boolean supports(final Class cls){
        return true;
    }
}