# Jonli HTTP laboratoriya va yangi model

Panel: http://127.0.0.1:8765/#lab. `start.cmd` bilan qayta ishga tushadi.
Hozirgi tayyor model `.runtime/http/bootstrap-model.json`da. Kundalik demo internet talab qilmaydi.

## Hakam uchun 3 daqiqalik tekshiruv

1. **Administrator → Jonli laboratoriya → To‘liq sinovni boshlash.**
   23 haqiqiy TCP so‘rov localhost serveriga boradi. Nazorat sinovida SQL-injection
   soxta SQLite bazasidan 3 qator qaytaradi. Himoyada HTTP 403 va
   `target_executed: false` ko‘rinadi. XSS/path traversal faqat so‘rov probralari;
   browserda script, OS buyruqlari yoki diskdagi maxfiy fayllar ishlatilmaydi.
2. **O‘zim so‘rov beraman**: `/search`ga `books` — oddiy so‘rov.
   `/search`ga `'/**/OR/**/1=1-- ` — oddiy signatura qoidasidan o‘tadigan SQL sintaksisi.
   Natijadagi `model_alert`, `rule_alert`, `blocked_by`, HTTP status va
   `target_executed`ni taqqoslang. Yangi so‘rovingizni ham kiritish mumkin.
3. **Faqat SOCga yuborish** tugmasi avtomatik bloklashni o‘chiradi.
   Yangi shubhali so‘rovni yuboring: **Insidentlar** va laboratoriyadagi SOC navbatida
   paydo bo‘ladi. Bu ilova ichidagi yetkazish; Telegram/email/SIEMga tashqi xabar
   jo‘natish hali sozlanmagan. Boshqa xodim paneli 5 soniyada yangilanadi.
4. Hodisada **Tekshirish va qaror**: `malicious/benign/uncertain`, sabab va amal.
   **Sessiyani bloklash** tanlansa, aynan o‘sha lokal sessiyaga blok qo‘yiladi;
   qo‘shimcha haqiqiy HTTP probe orqali 403 va nishon bajarilmagani tekshiriladi.
   **Sessiya blokini yechish** blokni bekor qiladi va qayta tekshiradi.
5. **Chiqish → Tasdiqlovchi**. Boshqa demo roli taklifni tasdiqlaydi.
   Aynan qaror vaqtidagi numeric featurelar, label, sabab/provenance, xodim amali va
   amal natijasi `http_feedback`ga yoziladi. Noaniq label treningga kirmaydi.
   Bu demo rollari bilan sinov; ikki haqiqiy inson tekshiruvi deb talqin qilinmaydi.
6. **AI/ML muhandisi** yangi dataset hashini tekshiradi, **HTTP modelni qayta
   o‘qitish**ni bosadi. Natija challenger; faol model o‘zgarmaydi.
   **Tasdiqlovchi** mezonlar o‘tgach uni faollashtiradi. Administrator mos schema
   bilan oldingi modelga qayta oladi. Qayta ishga tushirish qarorlarni saqlaydi.

## Dataset va o‘lchov

CSIC HTTP 2010 manbasi: [mualliflarning saqlangan hujjati](https://web.archive.org/web/20130924222653/http://iec.csic.es/dataset).
Mualliflar: Carmen Torrano Giménez, Alejandro Pérez Villegas, Gonzalo Álvarez Marañón.
Fayllar hujjatlashtirilgan GitHub mirroridan aniq commit va SHA-256 bilan olingan.
Bu e-commerce laboratoriyasida avtomatik yaratilgan ochiq HTTP trafik, **bankdan
olingan production log emas**. `anomalous` zararli bo‘lmagan noto‘g‘ri so‘rovlarni
ham o‘z ichiga oladi. Raw korpus faqat lokal `.runtime/public-data`da.

97 065 so‘rovdan model ishlatadigan featurelar bo‘yicha dublikatlar va qarama-qarshi
label guruhlari chiqarildi: **11 251 alohida namuna**. 7 790 train, 1 746 validation,
1 715 test. Train/validation/test guruhlari ajratilgan; bir xil model featurelari
ikki kesimga tushmaydi. Manbada ishonchli vaqt yo‘q, shu sababli vaqt bo‘yicha yoki
banklararo tekshiruv deb ko‘rsatilmaydi. Bu CSICning original normal-only
protokolidan farq qiladigan supervised repartition tajribasi.

64 daraxtli Random Forest. Threshold faqat validationda tanlanadi. Xuddi shu
feature extractor real requestga ham qo‘llanadi; cookie, parol, host, label va
kelajakdagi javob kodi model kirishiga berilmaydi. JSON inference sklearn bilan
solishtiriladi; pickle ishlatilmaydi. Transport/outcome ma’lumotlari faqat dataset
metadata bo‘lib qoladi. URL tuzilishi va parametr nomlari modeldan chiqarilgan.

| 1 715 namunali test | Precision | Recall | FPR |
|---|---:|---:|---:|
| Ushbu loyihadagi signatura qoidalari | 100.0% | 18.1% | 0.0% |
| O‘qitilgan model | 96.0% | 60.2% | 2.2% |
| AI + qoidalar | 96.0% | 60.3% | 2.2% |

AI qoidalar topmagan **338 anomal yozuvni** qo‘shimcha topdi, **20 qo‘shimcha yolg‘on
signal** berdi. Bu mavjud bank WAF/SIEM mahsulotiga qarshi taqqoslash emas.
Qat’iyroq bloklash thresholdida 414 true positive, 1 false positive.
Hisobot: `research/http-evaluation.json`. Takror ishlatilgan benchmark regression
dalili; yangi mustaqil bank validatsiyasi emas. Universal aniqlash kafolati yo‘q.

Yangi tasdiqlangan misol darhol vaznni o‘zgartirmaydi: guruhga qarab train yoki
holdoutga kiradi, public holdoutga teng featurelar treningga qayta kiritilmaydi.
Bir xil featurega qarama-qarshi xodim labeli kelsa, guruh karantinda qoladi.
Bir lab runining misollari guruhlanadi. Yetarli yangi sinf va vaqt xilma-xilligi
uchun keyinchalik bankning ruxsat etilgan Wazuh/Zeek/HTTP loglari kerak bo‘ladi.

## Takrorlash

```powershell
.\.venv\Scripts\python.exe scripts\train_http.py --download
.\.venv\Scripts\python.exe -m pytest -q
node scripts\check_frontend.mjs
.\start.ps1
```

`--download` faqat pinned ma’lumot fayllarini yuklaydi, undagi requestlarni bajarmaydi.
`SOC_MODE=pilot` laboratoriya hujum APIlarini o‘chiradi. Endpointlar boshqa host,
port yoki URL qabul qilmaydi; localhost server ham vaqtinchalik maxfiy sessiya va
aniq Host talab qiladi. Lab sessiyasi 30 minut; eski sessiyaga amal qilish aniq
`LAB_SESSION_EXPIRED` xatosini beradi. Qayta sinov yangi sessiya yaratadi.

HTTP specialist dataseti `soc-http-v2`, mavjud kontekst modelining dataseti
`soc-context-v1`; ular aralashtirilmaydi. Mavjud Wazuh/Zeek importlari saqlangan.
Kontekst model hali sintetik seedga tayangan; real bank firewall/EDR/IAM adapteri
hamon simulator. Real bankni himoya qilish uchun collector, bankka mos model
validatsiyasi va tasdiqlangan response adapterini alohida ulash kerak.
