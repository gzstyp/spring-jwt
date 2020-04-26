package com.fwtai.tool;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Enumeration;
import java.util.HashMap;

/**
 * 在controller层里{{不使用成员变量，而使用局部变量，因为局部变量在每个线程中都有各自的实例}}
 * @作者 田应平
 * @版本 v1.0
 * @创建时间 2020-04-26 10:38
 * @QQ号码 444141300
 * @Email service@dwlai.com
 * @官网 http://www.fwtai.com
*/
public final class ToolClient{

    public final static String executeRows(final int rows){
        final JSONObject json = new JSONObject();
        if(rows > 0){
            json.put("code",200);
            json.put("msg","操作成功");
            json.put("data",rows);
            return json.toJSONString();
        }else{
            json.put("code",199);
            json.put("msg","操作失败");
            json.put("data",rows);
            return json.toJSONString();
        }
    }

    public final static String createJson(final String code,final String msg){
        final JSONObject json = new JSONObject();
        json.put("code",code);
        json.put("msg",msg);
        return json.toJSONString();
    }

    public final static String createJsonFail(final String msg){
        final JSONObject json = new JSONObject();
        json.put("code",199);
        json.put("msg",msg);
        return json.toJSONString();
    }

    /**返回json字符串的token */
    public final static String createToken(final String token){
        final JSONObject json = new JSONObject();
        json.put("code",200);
        json.put("token",token);
        return json.toJSONString();
    }

    public final static String createJsonSuccess(final String msg){
        final JSONObject json = new JSONObject();
        json.put("code",200);
        json.put("msg",msg);
        return json.toJSONString();
    }

    public final static void responseJson(final String json){
        final HttpServletResponse response = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getResponse();
        response.setContentType("text/html;charset=utf-8");
        response.setHeader("Cache-Control","no-cache");
        PrintWriter writer = null;
        try {
            writer = response.getWriter();
            writer.write(String.valueOf(JSON.parse(json)));
            writer.flush();
        }catch (IOException e){
            e.printStackTrace();
        }finally{
            if(writer != null){
                writer.close();
                writer = null;
            }
        }
    }

    public final static HashMap<String,String> getFormParams(final HttpServletRequest request){
        final HashMap<String,String> params = new HashMap<String,String>();
        final Enumeration<String> paramNames = request.getParameterNames();
        while(paramNames.hasMoreElements()){
            final String key = paramNames.nextElement();
            if(key.equals("_"))continue;
            final String value = request.getParameter(key);
            if(value != null && value.length() >0){
                if(value.length() == 1 && value.equals("_"))
                    continue;
                params.put(key,value.trim());
            }
        }
        return params;
    }

    public final static void responseJson(final String json,final HttpServletResponse response){
        response.setContentType("text/html;charset=utf-8");
        response.setHeader("Cache-Control","no-cache");
        PrintWriter writer = null;
        try {
            writer = response.getWriter();
            writer.write(String.valueOf(JSON.parse(json)));
            writer.flush();
        }catch (IOException e){
            e.printStackTrace();
        }finally{
            if(writer != null){
                writer.close();
                writer = null;
            }
        }
    }
}