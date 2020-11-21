## Intro
這次是我第一次參加金盾, 靠著隊友 Carry 才偷到嶄露頭角獎, 因為最近比賽太多狀況有點差, 結果一題都沒解出來 QQ, 我發誓不會再有比賽 0 題貢獻的情況了= =

這次 web 題目感覺是滲透偏多, binary 則是屬於正常 binary exploit, 有些工具沒有準備齊全, 還有分析題目的角度沒磨練, 很慢才抓住重點

## 1
### 分析
tomcat 開 8080 跟 8009, 並透過 dirsearch 找到 `password.txt`, 後來就沒後來了.

聽 Racter 說有掃到 `/Login` 之類的 page, 透過 `password.txt` 得到的 user/pass 即可登入拿到 Flag

### 檢討
在解這題時一開始沒用 `nmap` 掃開的服務, `dirsearch` 掃伺服器架構, 原本以為是正常的 web 題, 可能偏向繞過某些 filter, 結果是題目偏滲透, 失策失策

## 2
### 分析
題目敘述我只記得阿土在搞事, 其他都忘記了XD

點進去是一個 apache 預設頁面, 根據題目提示發現 source code 有 ssh user/pass, 索性拿來登入, 發現馬上就被 close 掉. 根據提示, 必須使用 `ssh -L -N user@host` 來進行連線, 據說是做 proxy forward.

掃完 port 發現 database 使用 postgreSQL, 並且版本過舊, 所以有 CVE 可以打, 不過 postgreSQL 預設只開放 local 才能連, 因此得想辦法 touch 到 server 的 local 環境.

使用為 `ssh -L -N 8080:localhost:5432 admin@server`, 我為 client 的 8080 port 會接到 server 的 localhost:5432, 配合 `-N` 建立連線後不執行 command, 所以連線也就不會中斷, 因此可以在 local 打 CVE exploit. 因此可以繞過

1. ssh 連線馬上關閉 ==> `-N`
2. touch 不到 postgre ==> `-L 8080:localhost:5432`

做完上個步驟後, 透過提供的 CVE 與現成的 metasploit payload 來做攻擊, 並且取得 shell. 拿到 shell 後, 跑某個 `/bin/KXXXX` 指令就可以拿到 Flag 了

### 檢討
metasploit 裝起來www, 當初不太懂 `ssh -L -N` 的用途, 也不懂整個流程該做什麼, 後來看了手冊 `-L` 與 `-N` 的介紹與詢問他人, 才比較了解一些.
```
-L [bind_address:]port:host:hostport
-L [bind_address:]port:remote_socket
-L local_socket:host:hostport
-L local_socket:remote_socket
    Specifies that connections to the given TCP port or Unix socket on the local (client) host are to be forwarded to the given host and port, or Unix socket, on the remote side.  This
    works by allocating a socket to listen to either a TCP port on the local side, optionally bound to the specified bind_address, or to a Unix socket.  Whenever a connection is made to the
    local port or socket, the connection is forwarded over the secure channel, and a connection is made to either host port hostport, or the Unix socket remote_socket, from the remote
    machine.

    Port forwardings can also be specified in the configuration file.  Only the superuser can forward privileged ports.  IPv6 addresses can be specified by enclosing the address in square
    brackets.

    By default, the local port is bound in accordance with the GatewayPorts setting.  However, an explicit bind_address may be used to bind the connection to a specific address.  The
    bind_address of “localhost” indicates that the listening port be bound for local use only, while an empty address or ‘*’ indicates that the port should be available from all interfaces.


-N  Do not execute a remote command.  This is useful for just forwarding ports.
```

## 3
### 分析
目標是取得 `/etc/passwd`, 有個 `?file=test.png` 的 request query 可以使用, 但內容包含 `passwd` 的 request 不能送出. request 結束後會下載以 `upload` 為前綴的檔案, 並 filtewr 掉幾個 char `*`, `/` 等等. 後來透過查看 `domain/error.log` 才得知 upload_ 並不會在 file_include 前自動加上, 而是在送 response 才會在 file 前面補上這個 prefix. 一開始誤判, 導致以為此題的考試點是要繞掉黑名單 QQ, 解題前真的要多 scan

第一步主要是透過 `dirsearch` 找到 `/xml/xmltest.php`, 並且透過 `?file=/../xml/xmltest.php` 來下載此檔案

下載檔案後, 第二步就是 XXE 注入了, 我對 XXE 其實超不熟, 都沒有打過類似的題目, 所以在賽後只能透過他人分析結果來還原了. 以下為 payload:
```php
$todo = "待補";
```

## 5 (還某題 ?)
### 分析 + 題解
為一個提供加法服務的 server (nginx <---> flask), 且給 nginx_config (如下), 可以存取 `/template/index` 的樣子, 但是存取 `app.py` 時被擋了下來
```
server {
    listen 80;
    server_name _;

    location =/robots.txt {
        alias /home/nccst/CSC/flask_web/app/files/robots.txt;
    }

    location /admin {
        return 403;
    }

    location /files {
        alias /home/nccst/CSC/flask_web/app/files/;
    }

    location / {
        proxy_pass http://127.0.0.1:5000;
    }
}
```
不過這個 config 是有問題的, 如果我們存取 `/files../app.py`, 根據 `nginx_config`, 他會幫我們轉成 `app/files/../app.py`, 我們就能拿到 `app.py` 了.

(以下記憶瑣碎, 可能有些出入)

取得 `app.py` 後, 似乎還要取得某個其他位置的 source code, 並從 internal error 500 中取得 AUTH_KEY, 最後透過 `curl` (似乎是 cmdi) 來得到 Flag.

### 題解
主要應該是 **DTD 與 XXE 的關係 不懂**, 其他如 metasploit 沒載+不會用, 一開始沒有用 dirsearch 來取得伺服器的目錄架構等等

## 8
### 分析 + 題解
binary exploit. 印象記得是看似簡單的 ROP chain, canary 都關掉了, 實際上有 `seccomp` 保護, 他能限制可以使用的 instruction, 如果不小心使用到, 則會觸發 error handler.

隊友發現 `seccomp` 在比較 syscall 時, 是使用 `rax` 來比對, 而 syscall 其實只有看 `eax`, 所以可以在 rax 塞一個如 `0x1000000001` 的值在 `rax`, 這樣就能 bypass `seccomp` 了

## IOT exploit
### 1. 咖啡機密碼破解
取得 apk 後, dump apk 並解壓縮拿到原始碼, 因為要破解的密碼是藍芽連線, 所以直接看與藍芽連線有關的 code, 一步一步追 (逆向), 最後取得加密演算法, 得到 password.

### 2. 無人車 hijack
這題記得不是很清楚了, 似乎是側錄流量, 並且從封包中分析出有關無人車移動的資訊 (server, 方向, 速度等等). 在利用 `hydra` 硬是爆出 control server 的後臺帳號密碼. 最後在後台更新移動方向之類的 value

### 3. 自駕車突破速度上限
自駕車會定期與安全鎖傳送封包來訊息交流, 先用 ARP Spoofing 攔截自駕車傳送給安全鎖的封包, 從封包取得 user/pass info 後, 也可以分析封包的架構.

攔截封包後, 可以直接更動封包內容, 在其中加上/更改原本的資料, 例如改動速度上限的資料 (?), 並且在重新 forwared 給原 server (安全鎖).

總：攔截封包 => 改動資料 => 突破速度上限

## Conclusion
總而言之, 這次 web 答題不是很好, 應該先熟悉好工具(nmap, dirsearch and metasploit), 以及培養可以迅速查 CVE 的能力. 像一些 web 基本功 (XXE), 實在是太弱了, 所以才沒解掉ww

除了複習基本功之外, 還有可以多打打滲透相關的題目 如 `hackthebox`, 培養觀察漏洞的靈敏度, 以及多熟悉 metasploit XDD