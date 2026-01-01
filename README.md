## 記得pip install cryptography

## 記得下載conda-forge
```
conda activate base
conda install -c conda-forge gmpy2
```

## vscode 記得使用專用終端機執行
或者存成 檔名.py 直接跑 python 檔名.py

## 程式碼主流程
```
demo()
 ├─ 初始化玩具群組參數 (p, q, g)
 ├─ Alice / Bob 產生長期金鑰
 ├─ SCS1:
 │   ├─ Alice Signcrypt（逐步列印）
 │   ├─ Bob   Unsigncrypt（逐步列印）
 │   └─ 驗證成功
 ├─ SCS2:
 │   ├─ Alice Signcrypt（逐步列印）
 │   ├─ Bob   Unsigncrypt（逐步列印）
 │   └─ 驗證成功
 └─ Tamper Tests（竄改測試）
     ├─ 改 r
     └─ 改密文 c
```

### 1.系統初始化
建立 DSA-style 群組參數 (p, q, g)（示範用小參數）
Alice / Bob 各自產生長期金鑰
私鑰 x
公鑰 y = g^x mod p

### 2.Signcryption（Alice → Bob）
Alice 產生一次性隨機值 x
計算 Diffie–Hellman 共享金鑰
* k = y_b^x mod p

以 KDF 將 k 拆分為：
* k1：對稱加密金鑰（AES-GCM）
* k2：Keyed-hash 金鑰

計算
* r = KH_{k2}(m)

計算簽章值 s
* SCS1：s = x / (r + x_a) mod q
* SCS2：s = x / (1 + x_a * r) mod q

使用 k1 加密訊息，得到密文 c
傳送 (c, r, s)

### 3.Unsigncryption（Bob）
Bob 依 (r, s) 與 Alice 公鑰重建共享金鑰 k
將 k 拆分為 (k1, k2)
使用 k1 解密密文 c 得到 m

驗證
* KH_{k2}(m) == r

驗證成功即接受訊息

### 4.安全性測試（Demo）
竄改 r → 驗證失敗
竄改密文 c → AES-GCM 驗證失敗
