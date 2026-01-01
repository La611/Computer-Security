## 整體架構
```
main
 └─ run_once()
     ├─ 產生群組參數 (p, q, g)
     ├─ Alice / Bob 金鑰產生
     ├─ 傳統流程：
     │    Schnorr Sign → ElGamal Encrypt
     │    ElGamal Decrypt → Schnorr Verify
     ├─ Signcryption 流程：
     │    SCS1-like Signcrypt
     │    SCS1-like Unsigncrypt
     └─ 比較 powmod / inverse / time
```
### 重點工具：計算成本計數器
```
CTR.powmods += 1
```
每次 模指數運算 都會被計數
因為在公開金鑰密碼中：
* powmod 是最昂貴的操作

### 群組與金鑰產生
``make_demo_group()``
* 建立一個 safe-prime 形式的群組
* p = 2q + 1
* g 為 order q 的生成元
``keygen()``
```
x ← random
y = g^x mod p
```
* Alice / Bob 各自有 (x, y)
### 傳統流程：Sign-then-Encrypt
A. Schnorr Signature
``schnorr_sign()``
```
r = g^k
e = H(m || r)
s = k + e·skA mod q
```
``schnorr_verify()``
```
v = g^s · y^{-e}
verify H(m || v) == e
```
👉 需要 多次模指數運算

### B. ElGamal Hybrid Encryption
```
c1 = g^k
shared = yB^k
c2 = Enc(shared, message || signature)
```
📌 簽章與加密完全獨立執行

### Signcryption 流程（SCS1-like）
```
signcrypt_scs1()
x ← random
k = yB^x
(k1, k2) = KDF(k)
r = H_{k2}(m)
s = x / (r + skA) mod q
c = Enc_{k1}(m)
```
📌 單一流程同時完成簽章 + 加密
```
unsigncrypt_scs1()
k = (yA · g^r)^(s·skB)
m = Dec_{k1}(c)
verify H_{k2}(m) == r
```
📌 驗證與解密同時完成

### run_once()：比較與驗證
* 重置計數器
* 執行兩種流程
* 比較：
  * powmods 次數
  * invmod 次數
* 實際執行時間

* 範例輸出：
```
[Traditional] powmods=9
[Signcryption] powmods=4
Powmod reduction ≈ 55%
```
👉 驗證 Signcryption 在計算成本上的優勢
