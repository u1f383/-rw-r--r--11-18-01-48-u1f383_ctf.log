## Intro
這次 hitcon 卡了一個 malware 實戰課程以及交大網路程式設計作業，沒有花太多時間打QQ，加上隊友也有各自的事情要忙，所以成績沒有很理想 (X，不過花了 3, 40 分鐘解掉最水的一題，所以來記錄一下...

## AC1750
首先看到題目附了一個 pcap 檔，第一件事情就是先用 wireshark 開，瀏覽了一下，能猜到是存取某個 router interface 的流量紀錄。

那時看流量時，有找到一個附上 password 的 packet, 就以為那個很重要，被耽誤了一下QQ。其實要找的是**關於 AC1750 這台 router 的資訊**，包括其**過去的 vulnerability, 一些 default setting**。

然而就這樣找到一篇蠻近期的文章，主要是長亭紀錄挖掘 AC1750 的洞，從 recon 到 RCE 的完整紀錄，主要有幾個重點：

```
在 tdpServer 上 0.0.0.0 UDP 端口 20002 的守護進程在做監聽，目前尚未完全瞭解守護進程的整體功能，這對於開發者來說是不必要的。但是，該守護進程似乎是 TP-Link 移動應用程序和路由器之間的橋樑，從而允許從移動應用程序建立某種控制。
...

如上一節所述，數據包使用固定密鑰爲 TPONEMESH_Kf!xn?gj6pMAt-wBNV_TDP 的 AES 加密。不過，這個難題還有一些遺漏的部分。密碼用於 CBC 模式，IV 爲 1234567890abcdef1234567890abcdef 固定值。此外，儘管有 256 位密鑰和 IV，但實際使用的算法是有 128 位密鑰的 AES-CBC，因此未使用密鑰和 IV 的一半。
...
```

看到這些，會先想去撈 udp protocol 且 port eq 20002 的封包出來看。payload 明顯的被加密，而仔細看會有許多重複出現的部分，此為 CBC 的特徵。又因為 key 固定、IV 固定，先隨便選一個封包，再找一個線上 tool 去解密 payload，會長得像：

```
Ù.ièe@ù.Ul¯u.1ú]Kà^V@NY\  >.8.j.ºe_key_offer", "data": {"group_id": "1234", "ip": "1.3.3.7", "slave_mac": "';sh f;'", "slave_private_account": "aaaaa", "slave_private_password": "aaaaa", "want_to_join": false, "model": "owned", "product_type": "archer", "op
```

看到 `';sh f;'`，對應文章內容，很明顯就是在打這個 CVE，而藏 flag 的地方一定會再封包內部，所以會猜是不是要執行的 command 中會有 `echo flag` 或是 touch flag 等等 command，所以直接一包一包解密，最後會得到 `echo hitcon{Why_can_one_place_be_injected_twice}`，得到 flag `hitcon{Why_can_one_place_be_injected_twice}`。

REF: https://www.chainnews.com/zh-hant/articles/699951583501.htm

