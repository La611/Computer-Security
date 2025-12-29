3.1 最小展示腳本（你可照這個順序跑）

設定一組 (p,q,g)（DSA 子群型參數：q | (p-1)，g 為 order q 的生成元）

alice = keygen(params)、bob = keygen(params)

c,r,s = signcrypt_SCS1(params, alice, bob.y, m)（或 SCS2）

m2 = unsigncrypt_SCS1(params, alice.y, bob, c, r, s)

輸出：

m == m2

若你故意改 c 或 r 或 s，會 Verification failed
