package com.cosyit.shiro.helloworld;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Quickstart {

    private static final transient Logger log = LoggerFactory.getLogger(Quickstart.class);

    public static void main(String[] args) {
        /**
         * 搭建shiro环境。
         */
        //这是最简单的！
        // 用ini配置文件[realms,users,roles,permissions]的方式
        // 来创建一个SecurityManager 安全管理器 --  佟哥说这两行代码不是重要的。
        IniSecurityManagerFactory factory = new IniSecurityManagerFactory("classpath:shiro.ini");
        SecurityManager securityManager = factory.getInstance();

        //让其在JVM中，是单实例被访问的。  大部分应用都不会这样做，可能是用第三方的来管理的。
        SecurityUtils.setSecurityManager(securityManager);
        //当写完这行代码之后，shiro的环境就算是简单的搭建好了。我们来看如何操作shiro

        /**
         * 环境搭建好了之后，看看如何使用shiro.
         */

        //get currently executing user.获取当前操作的用户Subject. __Equivalence__ 等价于
        //fixme 重要等级 *****
        Subject subject__Equivalence__CurrentUser = SecurityUtils.getSubject();
        //接下来给大家讲一个故事，subject 用户的故事。一切的故事，都是从这个subject用户 围绕展开的。


        //测试使用session , 即便没有web容器 和 EJB容器 的情况下，也可以使用session.
        Session session = subject__Equivalence__CurrentUser.getSession();
        //session 就类似web 中的session，可以取存数据。
        session.setAttribute("对象A", "偶遇一位雍容华贵的少妇 spring security Manager.");
        session.setAttribute("对象B", "偶遇一位美丽的动人，苗条的姑娘 shiro");
        log.info("subject出过的对象:"+session.getAttributeKeys());
        log.info("发现并不合适,决定分手！");
        session.removeAttribute("对象A");
        String value = (String) session.getAttribute("k1");
        System.out.println(value);
        //已演示了session的存取，是不是和web的session一样的代码。


        //fixme 重要等级 *****
        //测试当前的用户是否已经被认证。即是否已经登录。
        //登录前是不会被认证的，只有登录后，才会被认证。
        if (!subject__Equivalence__CurrentUser.isAuthenticated()) {
            UsernamePasswordToken token = new UsernamePasswordToken("dawei.wang.o", "root");
            token.setRememberMe(true); //这个代码什么意思，不能瞎猜，先放在这里，下次我再讲。
            log.info("--------------");
            try {
                //执行登录。
                subject__Equivalence__CurrentUser.login(token);
                log.info(" ---- > 看看手持此令牌进行登录的人 : "+token.getPrincipal()); //看看手持此令牌进行登录的人。
            } catch (UnknownAccountException e) {
                e.printStackTrace();
            } catch (IncorrectCredentialsException e) {
                e.printStackTrace();
            }
            catch (LockedAccountException e) {
                e.printStackTrace();
            }catch (AuthenticationException e) {
                e.printStackTrace();
            }


            //如果登录没有异常，那么就会走到这里。   session.getPrincipal()   看看当前都有哪些人登录了。
            log.info("---->User ["+subject__Equivalence__CurrentUser.getPrincipal() +"] logged in successfully !");

            //判断是否有权限。
            if(subject__Equivalence__CurrentUser.hasRole("schwartz")){
                log.info("May the Schwartz be with you !");
            }else {
                log.info("hello , mere mortal .");
            }


            //fixme *** 测试用户是否具备某一个行为[权限]。 subject[user].isPermitted
            boolean permitted = subject__Equivalence__CurrentUser.isPermitted("ES6:driver");
            System.out.println(permitted);

            //登出系统。
            subject__Equivalence__CurrentUser.logout();

            System.exit(0);
        }

    }
}
