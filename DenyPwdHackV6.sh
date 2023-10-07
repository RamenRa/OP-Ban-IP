#!/bin/bash
## 本脚本基于iptables/ip6tables 和 ipset实现

Failed_times=4  ## 失败次数
findtime=3600  # 查找日志时间范围，单位：秒
bantime=24  # 黑名单过期时间,单位：小时 至少要大于 findtime/3600 

## 日志路径
LOG_DEST=/tmp/BanIP.log  # 不要随意删除 解除黑名单依赖BanIP.log
LOG_HISTORY=/tmp/BanHistory.log  # 操作日志和到期释放的IP

MAX_SIZE=50000  # 设置最大文件大小 单位：B

## 白名单IPV4 用"|"号隔开,支持grep的正则表达式
exclude_ipv4="192.168.4.|127.0.0.1"

## 日志关键字,每个关键字可以用"|"号隔开,支持grep的正则表达式
## 注: SSH 攻击四种关键字：Invalid user/Failed password for/Received disconnect from/Disconnected from authenticating
##     Luci 攻击"luci: failed login on / for root from xx.xx.xx.xx"
LOG_KEY_WORD="auth\.info\s+sshd.*Failed password for \
|luci:\s+failed\s+login \
|auth\.info.*sshd.*Connection closed by.*port.*preauth \
|Bad\s+password\s+attempt\s+for"

regex_IPV4="^((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})(\.((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})){3}[:0-9]{0,6}$"
regex_IPV6="^([a-f0-9]{1,4}(:[a-f0-9]{1,4}){7}|[a-f0-9]{1,4}(:[a-f0-9]{1,4}){0,7}::[a-f0-9]{0,4}(:[a-f0-9]{1,4}){0,7})[:0-9]{0,6}$"

function replace_backslashes {
  local input="$1"
  local replaced="${input//\\/\\\\\\}"  # 使用参数替换来进行替换
  echo "$replaced"
}

# 将'\'变成'\\\'
LOG_KEY_WORD=$(replace_backslashes "$LOG_KEY_WORD")
regex_IPV4=$(replace_backslashes "$regex_IPV4")


## 日志时间
LOG_DT=`date "+%Y-%m-%d %H:%M:%S"`

## 用于返回"Tue Oct 3 23:02:25 2023"时间格式的unix时间戳
function get_unix_time {
  local mon="$2"
  local day="$3"
  local time_str="$4"
  local year="$5"

  local array=(${time_str//:/ })
  local hour="${array[0]}"
  local min="${array[1]}"
  local sec="${array[2]}"

  case $mon in
    "Jan") month="1" ;;
    "Feb") month="2" ;;
    "Mar") month="3" ;;
    "Apr") month="4" ;;
    "May") month="5" ;;
    "Jun") month="6" ;;
    "Jul") month="7" ;;
    "Aug") month="8" ;;
    "Sep") month="9" ;;
    "Oct") month="10" ;;
    "Nov") month="11" ;;
    "Dec") month="12" ;;
    *) month="0" ;;  # Handle unknown month
  esac

  if [ "$month" != "0" ]; then
    datetime="$year-$month-$day $hour:$min:$sec"
    unix_timestamp=$(date -d "$datetime" "+%s")
    echo -e "$unix_timestamp"
  else
    echo "Invalid month: $mon"
  fi
}

## 返回 时间范围内的日志
function process_logread_output {
  local logread_output="$1"
  local threshold="$2"  ## 新增的参数用于表示时间差的阈值
  local output=""
  # 获取当前时间戳
  current_timestamp=$(date +%s)
  while IFS= read -r line; do
    # 提取日志中的时间部分
    log_time=$(echo "$line" | awk '{print $1, $2, $3, $4, $5}')
    # 将时间转换为时间戳
    # timestamp=$(date -d "$log_time" +%s 2>/dev/null)
    timestamp=$(get_unix_time $log_time)
    if [ -n "$timestamp" ]; then
      # 计算时间戳差值
      time_diff=$((current_timestamp - timestamp))
      # 如果差值小于threshold秒，则输出时间戳和原始日志行
      if [ "$time_diff" -lt "$threshold" ]; then
        # 将结果写入输出变量
        output+="$line\n"
      else
        break   # 否则退出查找
      fi
    fi
  done <<< "$logread_output"  # 通过 <<< 运算符传递logread的输出
  # 返回所有echo输出的内容
 echo -e "$output"
}

# 使用logread命令获取日志并调用函数
logread_output=$(logread | awk '{a[i++]=$0} END {for (j=i-1; j>=0;) print a[j--] }')
# logread_output=$(logread) 
log_output=$(process_logread_output "$logread_output" "$findtime")


# 从logread获取违规信息
function DenyIP_FromLog {
  local exclude_lo="$1"
  local regex="$2"

  # 使用awk来处理日志输出
  get_DenyIP=$(echo "$log_output" | awk -v keyword="$LOG_KEY_WORD" -v exclude="$exclude_lo" -v failed="$Failed_times" -v regex="$regex" '
    BEGIN {
      OFS="\n"
    }
    $0 ~ keyword {
      for (i = 1; i <= NF; i++) {
        if ($i ~ regex) { # 使用变量 regex 来匹配正则表达式
          ip = $i
          gsub(/:[0-9]+$/, "", ip) # 删除端口号
          if (ip != exclude) {
            ip_count[ip]++
          }
        }
      }
    }
    END {
      for (ip in ip_count) {
        if (ip_count[ip] > failed) {
          print ip
        }
      }
    }' | sort -u)
  # 返回处理结果
  echo "$get_DenyIP"
}
# 调用函数并传入参数
DenyIPLIst=$(DenyIP_FromLog "$exclude_ipv4" "$regex_IPV4")
# echo "$DenyIPLIst"
DenyIPLIstIPV6=$(DenyIP_FromLog "" "$regex_IPV6")
# echo "$DenyIPLIstIPV6"

# 统计ip 每行一个ip 统计行数即可
IPList_sum=$(awk 'END {print NR}' <<< "$DenyIPLIst")
IPList_sumIPV6=$(awk 'END {print NR}' <<< "$DenyIPLIstIPV6")

## IP集合名称
ChainName=DenyPwdHack
ChainNameV6=DenyPwdHack6

# 遍历违规IPV4和IPV6 并添加进黑名单集合
function DenyIPList_check {
  local ChainNameRule="$3"
  local IP_sum="$4"
  local DenyIPLIst_local="$5"
  local IP_TOOL="$1"
  local IP_CLASS="$2"
  
  # 检查集合是否已经存在
  ipset_exists=$(ipset list | grep -q "$ChainNameRule" && echo "yes" || echo "no")
  if [ "$ipset_exists" = "no" ]; then
  # 如果集合不存在，创建它.
    echo "[$LOG_DT]  ipset create $ChainNameRule hash:ip $IP_CLASS" >> $LOG_HISTORY
    ipset create "$ChainNameRule" hash:ip $IP_CLASS
  fi
  if [[ $IP_sum -ne 0 ]]; then
    current_timestamp=$(date +%s)   # 获取当前时间戳
    for i in ${DenyIPLIst_local}; do
      if ! ipset test "$ChainNameRule" "$i" 2>&1 | grep -q "is in set $ChainNameRule"; then
        ipset add "$ChainNameRule" "$i" 2>/dev/null \
        && echo "[$LOG_DT] BAN_IP $i rule $ChainNameRule unix $current_timestamp" >> "$LOG_DEST"
      fi
      if ! "$IP_TOOL" -C INPUT -m set --match-set "$ChainNameRule" src -j DROP 2>/dev/null; then
        "$IP_TOOL" -I INPUT -m set --match-set "$ChainNameRule" src -j DROP \
        && echo "[$LOG_DT]  "$IP_TOOL" -I INPUT -m set --match-set $ChainNameRule src -j DROP" >> "$LOG_HISTORY"
      fi
    done
  fi
}
DenyIPList_check "iptables" "" "$ChainName" "$IPList_sum" "$DenyIPLIst" 
DenyIPList_check "ip6tables" "family inet6" "$ChainNameV6" "$IPList_sumIPV6" "$DenyIPLIstIPV6" 

# 检查日志是否存在以及限制大小
function check_log {
  local log_name="$1"
  # 检查日志文件是否存在
  if [ ! -f "$log_name" ]; then
    touch "$log_name"
  fi
  # 检查日志文件大小
  log_size=$(du -b "$log_name" | cut -f1)
  # 如果日志文件超过最大大小，则清空日志文件
  if [ "$log_size" -gt "$MAX_SIZE" ]; then
    echo "" > "$log_name"
  fi
}
# 检查日志
check_log "$LOG_DEST"
check_log "$LOG_HISTORY"

## 黑名单过期删除
current_timestamp=$(date +%s) # 获取当前unix时间戳
# 执行grep命令并逐行处理输出
grep "\] BAN_IP.*DenyPwdHack" $LOG_DEST | while read -r line; do
  # 提取行中的时间戳和IP地址
  ip=$(awk '{print $4}' <<< "$line")
  # 将时间戳转换为Unix时间戳
  timestamp_unix=$(awk '{print $8}' <<< "$line")

  # 计算时间差
  time_difference=$((current_timestamp - timestamp_unix))

  # 检查时间差是否超出
  if [ "$time_difference" -gt $(($bantime * 3600)) ]; then
    ipset del $ChainName $ip 2>/dev/null || ipset del $ChainNameV6 $ip 2>/dev/null
    formatted_timestamp=`date "+%Y-%m-%d %H:%M:%S"`  # 获得一个格式化的时间戳
    modified_line=$(sed 's/BAN_IP/Released/' <<< "$line" | awk -v ts="[$formatted_timestamp]" '{sub(/rule.*/, "in " ts)}1')
    echo "$modified_line" >> $LOG_HISTORY
  else
    echo "$line"
  fi
done > $LOG_DEST.tmp
# 将临时文件替换为原文件
mv $LOG_DEST.tmp $LOG_DEST
