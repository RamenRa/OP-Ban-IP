# OP-Ban-IP
[项目源地址](https://github.com/vimers01/deny-ssh-password-attack)
&ensp; 基于iptables/ip6tables和ipset**修改编写**了一个读取日志、封禁ip的小脚本, 脚本通过crontab定时执行。参数在脚本中修改。
## 本脚本基于iptables/ip6tables 和 ipset实现
### 操作步骤如下:
***

1. 下载文件DenyPwdHackV6.sh , 以root登录，放在 /root/ 目录下。然后执行  在Openwrt增加以下 crontab 内容:
```
chmod u+x /root/DenyPwdHackV6.sh
```

2. 执行命令: 
```
crontab -e
```

3. 按需要贴入以下内容: 
```
0 */3 * * * /root/DenyPwdHackV6.sh   # 每3 小时执行一次脚本例子
*/1 * * * * /root/DenyPwdHackV6.sh   # 每1分钟执行一次脚本例子
```

#### 查看封锁IP集合：
```
ipset list | awk '/Name: DenyPwdHack/,0'  # 如果没有显示ipv6的集合 'DenyPwdHack'替换成'DenyPwdHack6'
```
#### 手动删除规则：
```
ipset del DenyPwdHack 192.168.XX.XX  # ipv4规则  将IP替换为需要从黑名单移除的ip

ipset del DenyPwdHack6 fe80::        # ipv6规则 将IP替换为需要从黑名单移除的ip
```


#### 查看日志
```
cat /tmp/BanIP.log   # 已经禁止的IP
cat /tmp/BanHistory.log  # 历史禁止IP

```


### 脚本中的参数：
***

1. 登录失败多少次后封锁IP

   - Failed_times=4

2. 查找日志时间范围，单位：秒
   
   - findtime=3600

3. 黑名单过期时间,单位小时
 
   - BlackList_exp=24

4. 日志保存位置
 
   - LOG_DEST=/tmp/BanIP.log
   
   - LOG_HISTORY=/tmp/BanHistory.log

6. 白名单IP可以用"|"号隔开,支持grep的正则表达式
 
   - exclude_ip="192.168.4|127.0.0.1"

7. 日志大小限制 单位：B
   - MAX_SIZE=50000
