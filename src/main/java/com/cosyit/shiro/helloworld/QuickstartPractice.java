package com.cosyit.shiro.helloworld;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class QuickstartPractice {
    private static final transient Logger log = LoggerFactory.getLogger(Quickstart.class);

    public static void main(String[] args) {
        /**
         * 1.搭建shiro环境。 通过工厂创建一个安全管理器。
         */
        IniSecurityManagerFactory factory = new IniSecurityManagerFactory("classpath:shiro.ini");
        SecurityManager securityManager = factory.getInstance();

        //让我们的 securityManager 对象 在JVM中是以 单例的形式 来进行访问的。
        SecurityUtils.setSecurityManager(securityManager); //


        //subject 相当于用户。
        Subject subject = SecurityUtils.getSubject();

        Session session = subject.getSession();

        session.setAttribute("2018年12月21日 日志","日志状态：完成");
        Object attribute = session.getAttribute("2018年12月21日 日志");
        System.out.println(attribute);

        System.out.println(subject.isAuthenticated());//是否认真。


        //rememberMe 记住要轻一点， isAuthenticated 要更重一点，可以进行敏感访问的设计。
        if(!subject.isAuthenticated()){
            UsernamePasswordToken token = new UsernamePasswordToken("dawei.wang.o", "root");
            UsernamePasswordToken token2 = new UsernamePasswordToken("root", "secret");

            token.setRememberMe(true);//
           //执行登录
            try {
                System.out.println("登录前是否被认证:"+subject.isAuthenticated());
                //执行登录。
                subject.login(token);
                subject.login(token2);
                System.out.println("登录后是否被认证:"+subject.isAuthenticated());
                System.out.println("登录成功！！！");
                log.info(" ---- > 看看手持此令牌的登录人 : "+token.getPrincipal()); //看看手持此令牌进行登录的人。
                log.info(" ---- > 看看手持此令牌的登录人 : "+token2.getPrincipal()); //看看手持此令牌进行登录的人。
            } catch (UnknownAccountException e) {
                System.out.println("没有此用户");
            } catch (IncorrectCredentialsException e) {
                System.out.println("密码不对");
            }
            catch (LockedAccountException e) {
                System.out.println("此账户被锁住");
            }catch (AuthenticationException e) {
                e.printStackTrace();
            }
        }

        System.out.println(subject.hasRole("schwartz"));;

    }
}
