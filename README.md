1. 以字符为单位对sip消息进行解析。
2. 维护一个状态机，根据状态机的状态来进行状态转移。
3. 维护一些状态变量，用以记录整条sip消息的信息。
4. 对header进行注册式回调，当解析到对应header时，调用对应的回调函数。
5. 仅拷贝一次原始数据或从不拷贝，任何信息均由指针+长度表示。


# 其他材料：
- RFC3261

# 协议知识
1. header field字母大小写不敏感。
2. header 缩写表
Header Name (Long Format) Compact Format
Call-ID i
Contact m
Content-Encoding e
Content-Length l
Content-Type c
From f
Subject s
Supported k
To t
Via v

# sip structure
generic-message  =  start-line
                    *message-header
                    CRLF
                    [ message-body ]
start-line       =  Request-Line / Status-Line

Request-Line  =  Method SP Request-URI SP SIP-Version CRLF
Status-Line  =  SIP-Version SP Status-Code SP Reason-Phrase CRLF
