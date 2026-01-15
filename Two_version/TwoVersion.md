# TWO VERSION

***Bước 1:*** Phân tích đề

Chương trình tạo:

- `secret` = **16 bytes ngẫu nhiên** → dùng làm AES key (ECB) để mã hoá flag → `enc_flag`.
- Nhưng `secret` không được đưa ra trực tiếp, mà bị “bọc” qua **2 lớp RSA**:
  - **Version 1:** RSA chuẩn `N1 = pq`, nhưng số mũ bị gài: `e = e0 + k·phi(N1)`  
    (`e0` là prime 32-bit, `k` là số lớn 256-bit).
  - **Version 2:** RSA với `N2` là tích của **nhiều prime 128-bit liên tiếp** (dùng `next_prime`), mã hoá `hint_1` thành `ct`.

Mục tiêu: giải 2 lớp RSA để lấy lại `secret`, rồi giải AES để lấy flag.

---

***Bước 2:*** Phá Version 2 trước

`N2` không phải RSA 2 prime, mà là tích nhiều prime 128-bit **liền kề nhau** ⇒ dễ factor.

Cách làm:

- Ước lượng prime “trung bình” của `N2`: `r ≈ N2^(1/m)` (m ≈ 17).
- Quét `nextprime/prevprime` quanh `r` để tìm 1 ước chia hết `N2`.
- Khi có 1 prime divisor, ta lần `prevprime` xuống và `nextprime` lên để lấy đủ toàn bộ chuỗi prime.
- Tính `phi(N2) = ∏(pi - 1)`, đảo RSA:
  - `d2 = 65537^-1 mod phi(N2)`
  - `hint_1 = ct^d2 mod N2`

Kết quả: lấy lại **hint_1** (chính là “secret đã bị bọc version 1”).

---

***Bước 3:*** Phá Version 1 bằng “số mũ gài phi”

Version 1 tạo:

\[
e = e0 + k \cdot \varphi(N1)
\]

với e0 rất nhỏ (32-bit), k lớn.

Vì phi(N1) rất gần N1 ⇒ e/N1 ≈ k nên ta lấy:

- k = ceil(e/N1) = (e + N1 - 1)//N1
- phi1 = e//k
- e0 = e%k (e0 sẽ là prime 32-bit)

Có phi1 ⇒ factor N1:

- S = p + q = N1 - phi1 + 1
- Δ = S^2 - 4N1
- p = (S + sqrt(Δ))/2`, `q = (S - sqrt(Δ))/2

---

***Bước 4:*** Khôi phục secret & giải AES

Do:

\[
hint_1 = secret^{e} \bmod N1 = secret^{e0 + k\phi1} \bmod N1
\]

mà theo Euler secret^{phi1} ≡ 1 (mod N1)` ⇒ `secret^{kphi1} ≡ 1 nên:

\[
hint_1 \equiv secret^{e0} \pmod{N1}
\]

Vậy chỉ cần đảo `e0`:

- d0 = e0^-1 mod phi1
- secret = hint_1^d0 mod N1

Cuối cùng:

- key = secret (16 bytes)
- decrypt enc_flag bằng AES-ECB
- unpad PKCS#7 → ra flag.

---

***Bước 5:***Code và chạy terminal tìm FLAG
```css
from Crypto.Util.number import inverse, long_to_bytes, isPrime
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from math import isqrt
import sympy as sp
from sympy import integer_nthroot, nextprime, prevprime
# ========= INPUT =========
N1 = 17362209236509579956069121909745118765799063323981053744694079912565491761665470166232725041911668984587357851108379264256444768723119405696823379326603919936432028254892304111890799155248313945504362228086008054153337335473581045441412224034029131473052839257492200434841614255071621144691873145779936936466540564808189303815230586143579770974537663138227520239222958954087051769031139540550385941998442389661281975075970676604559169389854098177253292054675455122805187979417072249915003812124619547817345238821993663526288499599335194728734483790328454191490869993428411439760162813987746438088527227601749820028193

e = 568582705727074893855912262854931693776520061370825795622408975722616647195254499204299022659637745471845846557420791526279013376743846402285643895966976225319567903776419747592534878785237707018847064329521965900069329553901759652438404357571363572446084085687887505441095248254418448399269726503670730040360740992133710023103279528719378138713561929468837511729721619671738503296388639260766495550559585215630589053151303089778450120428975766990144168252012620202718975328284160837828555307103092360072925443331146944544205083563459507313906353592377402822356714725646404116880466954160143406854279706045105410824643858602601732293803652038686291057500387221541409697375265891315799717338405

N2 = 174553024057014543990096002679862638088905851653879673222226052298055708844181812197941875851675416263226641449259760427101268268472069203586567587515794891047875245725162110718082616270544366434288997011409037775968719808654349176938207119625705703790242080128391560864432915193871137643173668518980792686437123926377623591683827956931115090648091374719966673705080651380216030247495007008029626444956423886177383838787824634354346012965466030223117377462983842249633655418289489207513555281526739138705675027976815421110574047635449979101326595680755121900431939859745287285869554512425317799105125963506050787144028639637446623602111823871042061393

ct = 132963375508750110982747240401551817429093402914130496323529445591699573319732182982477592602548638283213896716757534905217268537453949332314065417291803810569772825403916533444924533708208557973427355332410755739881415766694571930525562269127527531894626120363166965760452473821975744785213257372447726685728346094300092678082137396501264318071662127385515962532743128346914780190335936819653183800050104005846840953382428383415290230446004794710008750774068731703819552901643139934566602333045031459877867709818046467532841903296594824234648604109806308639955400969917946294822261213855069675091607810871889832057748335243982627101739006805995485773

enc_flag = b'\xe23\x8c\x89~\xce\\\x10\x85\xa7\x92)\x17zPu\x17Ny1\x82\x1a\xf4\x1bS\xa8\xcb\xe2\xb7\xf4\x07\x84\x93\xe6{\xc308\x94\xd0\xcfg\x96\xf2\x8dd\xa4"'

# ========= STEP A: factor N2 via "consecutive 128-bit primes" =========
m = 17
r, _ = integer_nthroot(N2, m)
r = int(r)

def find_divisor_near(n, center, window=10000):
    up = int(nextprime(center))
    down = int(prevprime(center))
    for _ in range(window):
        if n % up == 0:
            return up
        if n % down == 0:
            return down
        up = int(nextprime(up))
        down = int(prevprime(down))
    return None

p_mid = find_divisor_near(N2, r)

# go down to smallest factor
p0 = p_mid
while True:
    q = int(prevprime(p0))
    if N2 % q == 0:
        p0 = q
    else:
        break

# go up to largest factor
plast = p_mid
while True:
    q = int(nextprime(plast))
    if N2 % q == 0:
        plast = q
    else:
        break

# collect all consecutive primes
factors = []
n_tmp = N2
cur = p0
while True:
    factors.append(cur)
    n_tmp //= cur
    if cur == plast:
        break
    cur = int(nextprime(cur))

assert n_tmp == 1 and len(factors) == 17

phi2 = 1
for pr in factors:
    phi2 *= (pr - 1)

d2 = inverse(0x10001, phi2)
hint = pow(ct, d2, N2)  # exact, because N2 > N1 here

# ========= STEP B: recover k, phi1, e0 from e =========
k = (e + N1 - 1) // N1          # ceil(e/N1)
e0 = e % k                      # 32-bit prime
phi1 = e // k                   # phi(N1)

assert e0.bit_length() <= 32 and isPrime(e0)

# factor N1 from phi1
s = N1 - phi1 + 1               # p+q
disc = s*s - 4*N1
t = isqrt(disc)
assert t*t == disc
p = (s + t)//2
q = (s - t)//2
assert p*q == N1

# recover secret
d0 = inverse(e0, phi1)
secret_int = pow(hint, d0, N1)
key = long_to_bytes(secret_int, 16)

# decrypt flag
pt = unpad(AES.new(key, AES.MODE_ECB).decrypt(enc_flag), 16)
print(pt.decode())
```
***Ta tìm được FLAG***
![alt text](image.png)

***FLAG:*** W1{L1ttl3's_ch4ll3ng3_1s_v3ry_e4sy_R1ght???}