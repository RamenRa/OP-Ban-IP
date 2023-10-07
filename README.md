# OP-Ban-IP
[项目源地址](https://github.com/vimers01/deny-ssh-password-attack)

&ensp; 基于iptables/ip6tables和ipset**修改编写**了一个读取日志、封禁ip的小脚本, 脚本通过crontab定时执行,**系统重启**后该脚本创建的**所有规则失效**。参数在脚本中修改。

&ensp; 官方的openwrt可以直接用‘fail2ban’，我使用的op版本添加‘luci’规则后依然不生效。
## 本脚本基于iptables/ip6tables 和 ipset实现
### 使用方法:
***

1. 以root登录 下载文件DenyPwdHackV6.sh 并修改权限:
```
wget https://github.com/RamenRa/OP-Ban-IP/blob/main/DenyPwdHackV6.sh  # 下载

chmod u+x /root/DenyPwdHackV6.sh   # 更改权限
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

### 后续操作方法：
***
#### 查看封锁IP集合：
```
ipset list | awk '/Name: DenyPwdHack/,0'  # 如果没有显示ipv6的集合 'DenyPwdHack'替换成'DenyPwdHack6'
```
#### 手动移除黑名单IP：
```
ipset del DenyPwdHack 192.168.XX.XX  # ipv4规则  将IP替换为需要从黑名单移除的ip 

ipset del DenyPwdHack6 fe80::        # ipv6规则 将IP替换为需要从黑名单移除的ip
```
移除后，下一次运行脚本如果违规IP的违规记录还在**查找日志时间范围 参数: findtime**之内。会被再次封禁！！

#### 查看日志
```
cat /tmp/BanIP.log   # 已经禁止的IP
cat /tmp/BanHistory.log  # 历史禁止IP

```

### 可选参数：
***
```
1. 登录失败多少次后封锁IP (整数)

Failed_times=4

2. 查找日志时间范围，单位：秒(整数)
   
findtime=3600

3. 黑名单过期时间,单位：小时(整数)
   
BlackList_exp=24  #至少要大于 findtime/3600

4. 日志保存位置
 
LOG_DEST=/tmp/BanIP.log
   
LOG_HISTORY=/tmp/BanHistory.log

6. 白名单IP可以用"|"号隔开,支持grep的正则表达式
 
exclude_ip="192.168.4|127.0.0.1"

7. 日志大小限制 单位：B(整数)
MAX_SIZE=50000
```


### 不重启 撤销脚本所有操作 (按顺序)
```
iptables -D INPUT -m set --match-set DenyPwdHack src -j DROP   # 删除IPV4防火墙规则 一般只需运行一次 可以在终端重复执行，直到提示规则不存在 
ip6tables -D INPUT -m set --match-set DenyPwdHack6 src -j DROP # 删除IPV6防火墙规则 一般只需运行一次 可以在终端重复执行，直到提示规则不存在

ipset destroy DenyPwdHack  # 删除整个IP集合
ipset destroy DenyPwdHack6  # 删除整个IPV6集合

rm /tmp/BanIP.log  # 删除日志
rm /tmp/BanHistory.log

```
