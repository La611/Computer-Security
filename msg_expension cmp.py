import random
import hashlib
from math import gcd

# 數學工具
def mod_inverse(a, m):      # 計算模逆元
    return pow(a, -1, m)

def generate_params(bits=256):
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F   # 256-bit 大質數 for demo
    g = 2    # 生成元
    return p, g

def hash_msg(msg_int, p):
    h = hashlib.sha256(str(msg_int).encode()).hexdigest()
    return int(h, 16) % (p - 1)



# 傳統 Sign-then-Encrypt
class ElGamal_StE:
    def __init__(self, p, g):
        self.p = p
        self.g = g

    def keygen(self):
        priv = random.randint(2, self.p - 2)  # 私鑰
        pub = pow(self.g, priv, self.p)       # 公鑰
        return priv, pub

    def sign(self, m, priv_key):     # ElGamal 簽章
        while True:
            k = random.randint(2, self.p - 2)
            if gcd(k, self.p - 1) == 1:
                break
        
        r = pow(self.g, k, self.p)
        k_inv = mod_inverse(k, self.p - 1)
        hm = hash_msg(m, self.p)
        s = (k_inv * (hm - priv_key * r)) % (self.p - 1)
        return (r, s)

    def encrypt(self, plaintext_int, pub_key):     # ElGamal 加密
        k = random.randint(2, self.p - 2)
        c1 = pow(self.g, k, self.p)
        c2 = (plaintext_int * pow(pub_key, k, self.p)) % self.p
        return (c1, c2)

    def process_flow(self, m, sender_priv, receiver_pub):  # 整體流程，先簽章再加密
        r, s = self.sign(m, sender_priv)

        enc_m = self.encrypt(m, receiver_pub)
        enc_r = self.encrypt(r, receiver_pub)
        enc_s = self.encrypt(s, receiver_pub)
        
        final_packet = (enc_m, enc_r, enc_s)
        return final_packet





# 簽密 
class Zheng_Signcryption:
    def __init__(self, p, g):
        self.p = p
        self.g = g

    def keygen(self):
        priv = random.randint(2, self.p - 2)
        pub = pow(self.g, priv, self.p)
        return priv, pub

    def signcrypt(self, m, sender_priv, receiver_pub):
        while True:
            # 1. 選擇隨機數 x (移入迴圈內，失敗時重選)
            x = random.randint(2, self.p - 2)
            
            # 2. 計算 K = (y_b)^x mod p
            K = pow(receiver_pub, x, self.p)
            
            # 3. c = m * K mod p
            c = (m * K) % self.p
            
            # 4. r = H(m + K)
            r = hash_msg(m + K, self.p)
            
            # 5. 計算 s 的分母: (r + x_a) mod (p-1)
            denom = (r + sender_priv) % (self.p - 1)
            
            # 6. 檢查是否存在模逆元 (即 gcd 為 1)
            # 如果 gcd != 1，代表無法計算 s，直接 continue 重跑迴圈選新的 x
            if gcd(denom, self.p - 1) != 1:
                continue
                
            # 若成功找到逆元，計算 s 並回傳
            # s = x / (r + x_a) mod (p-1)
            s = (x * mod_inverse(denom, self.p - 1)) % (self.p - 1)
            
            # 成功產生，跳出函式
            return (c, r, s)




# 比較分析
def main():
    print("=== 初始化密碼學參數 (256-bit prime) ===")
    p, g = generate_params()
    
    msg = 12345678901234567890       # 模擬訊息
    print(f"原始訊息 m: {msg}\n")

    # 1. Sign-then-Encrypt
    ste_sys = ElGamal_StE(p, g)
    alice_priv_ste, alice_pub_ste = ste_sys.keygen()
    bob_priv_ste, bob_pub_ste = ste_sys.keygen()
    
    ste_packet = ste_sys.process_flow(msg, alice_priv_ste, bob_pub_ste)
    


    # 2. Signcryption
    sc_sys = Zheng_Signcryption(p, g)
    alice_priv_sc, alice_pub_sc = sc_sys.keygen()
    bob_priv_sc, bob_pub_sc = sc_sys.keygen()
    
    sc_packet = sc_sys.signcrypt(msg, alice_priv_sc, bob_pub_sc)



    # 比較大小 Message Expansion
    def get_size(obj):   # 計算 tuple 中所有整數的位元組總和
        total_bytes = 0
        
        flat_list = []
        if isinstance(obj, tuple):
            for item in obj:
                if isinstance(item, tuple):
                    flat_list.extend(item)
                else:
                    flat_list.append(item)
        
        for num in flat_list:
            total_bytes += (num.bit_length() + 7) // 8
        return total_bytes, len(flat_list)

    size_ste, elem_ste = get_size(ste_packet)
    size_sc, elem_sc = get_size(sc_packet)
    size_msg = (msg.bit_length() + 7) // 8

    print("=== 比較結果 (Message Expansion Analysis) ===")
    print(f"{'項目':<25} | {'元素數量 (Elements)':<20} | {'總大小 (Bytes)*':<15}")
    print("-" * 65)
    print(f"{'原始訊息 (Message)':<25} | {'1 (m)':<20} | {size_msg:<15}")
    print(f"{'先簽後密 (StE)':<25} | {f'{elem_ste} (3 pairs)':<20} | {size_ste:<15}")
    print(f"{'簽密 (Signcryption)':<25} | {f'{elem_sc} (c, r, s)':<20} | {size_sc:<15}")
    print("-" * 65)
    
    expansion_ste = size_ste - size_msg
    expansion_sc = size_sc - size_msg
    
    print(f"\n[分析結論]")
    print(f"1. 先簽後密 (ElGamal+ElGamal) 產生了 {elem_ste} 個大整數。")
    print(f"   原因: 簽章產生(r,s)，接著加密 m,r,s。每個加密產生(c1,c2)，共 3x2=6 個元素。")
    print(f"2. 簽密 (Zheng) 僅產生 {elem_sc} 個大整數 (c, r, s)。")
    print(f"3. 節省空間: 簽密比傳統 StE 節省了約 {(1 - size_sc/size_ste)*100:.2f}% 的通訊成本。")
    print("\n*註: Bytes 計算僅包含數值本身的二進位大小，未包含 Python 物件 overhead。")

if __name__ == "__main__":
    main()