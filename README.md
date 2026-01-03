# Signcryption 實作與效能分析 (Signcryption vs. Traditional Approach)

本專案旨在實作 **Signcryption (簽密)** 技術，並將其與傳統的 **Sign-then-Encrypt (先簽章後加密)** 流程進行安全性、計算成本與通訊成本的比較。

專案主要展示了 Zheng 提出的 Signcryption 方案 (SCS1 與 SCS2)，並對比 Schnorr 簽章搭配 ElGamal 加密的傳統組合。

##  檔案結構說明

| 檔案名稱 | 描述 |
|:--- |:--- |
| `computer-security.py` | **主展示程式**。詳細列出 SCS1/SCS2 的簽密與解簽密流程、中間參數，並包含**竄改攻擊 (Tamper Tests)** 的安全性驗證。 |
| `computational_cost.py` | **計算成本分析**。統計並比較 Signcryption 與 Traditional 方法在模指數運算 (Modular Exponentiation) 上的次數差異。 |
| `msg_expension cmp.py` | **通訊成本分析**。比較兩種方式產生的訊息擴展 (Message Expansion) 與封包大小。 |
| `cmp_with_traditional.py` |  計算成本比較腳本。 |

---

##  環境建置 (Prerequisites)

本專案使用 Python 開發。建議使用 `conda` 環境以獲得最佳效能 (特別是 `gmpy2` 大數運算庫)。

### 1. 安裝基礎依賴
```bash
pip install cryptography
```
* `cryptography`: 用於 AES-GCM 對稱式加密 (若未安裝，程式會自動降級使用 XOR demo 實作)。

### 2. 安裝加速庫 (選用但強烈建議)
若無 `gmpy2`，程式仍可執行，但大數運算速度較慢且無法精確計算效能數據。
```bash
conda install -c conda-forge gmpy2
```

---

## 使用方式 (Usage)

### 1. 執行主流程展示
查看 SCS1/SCS2 詳細運作流程與安全性測試：
```bash
python computer-security.py
```
**輸出重點：**
* 初始化參數 (p, q, g)
* Alice/Bob 金鑰生成
* **SCS1 流程**：顯示 $r, s, c$ 計算過程與驗證結果。
* **SCS2 流程**：顯示變形後的計算過程。
* **安全性測試**：模擬竄改 $r$ 或密文 $c$，驗證系統是否能偵測並報錯 (InvalidTag/ValueError)。

### 2. 分析計算成本
比較模指數運算 (powmod) 的次數：
```bash
python computational_cost.py
```
**預期結果：**
Signcryption 方案通常能比傳統 Sign-then-Encrypt 減少約 **50% 以上** 的模指數運算成本。

### 3. 分析通訊大小
比較傳輸封包的大小：
```bash
python "msg_expension cmp.py"
```
**預期結果：**
Signcryption 因為不需要傳送獨立的簽章與公鑰加密後的簽章，僅需傳送 $(c, r, s)$，因此通訊成本顯著較低。

---

## 技術原理 (Technical Concepts)

### 傳統流程 (Traditional: Sign-then-Encrypt)
即 **Schnorr Signature** + **ElGamal Encryption**。
1. **簽章 (Sign)**: Alice 對訊息 $m$ 簽章，產生 $(r, s)$。
2. **加密 (Encrypt)**: Alice 將 $m, r, s$ 打包，使用 Bob 的公鑰加密。
3. **缺點**: 步驟分離，計算量大 (多次 exponentiation)，產出的密文長度較長。

### 簽密流程 (Signcryption)
基於 Zheng 的 SCS1 方案。
1. **單一邏輯運算**: 同時完成「簽章」與「金鑰交換」。
   * 計算 $K = y_B^x \pmod p$ (Diffie-Hellman shared secret)
   * 從 $K$ 衍生出加密金鑰 $k_1$ 與雜湊金鑰 $k_2$。
2. **簽章生成**: $s = x / (r + x_A) \pmod q$
3. **特點**:
   * 解簽密 (Unsigncrypt) 時，Bob 可一次還原金鑰 $K$ 並驗證來源。
   * **效率**: 大幅減少昂貴的模指數運算。

---

## 比較摘要

| 指標 | 傳統 (StE) | 簽密 (Signcryption) | 優勢 |
|:--- |:--- |:--- |:--- |
| **運算成本** | 高 (多次 powmod) | 低 (大幅減少 powmod) | 運算速度快 ~50% |
| **通訊成本** | 高 (密文 + 加密後的簽章) | 低 (緊湊的三元組 c, r, s) | 節省頻寬 |
| **實作複雜度** | 模組化 (簽章/加密分離) | 整合式 (邏輯耦合) | 效率優先 |

---

## 注意事項
* 本專案中的密碼學參數 (如 512-bit safe prime) 僅供**展示**使用，不建議直接用於生產環境。
* 隨機數生成使用 `os.urandom` 與 `secrets`，符合安全標準。