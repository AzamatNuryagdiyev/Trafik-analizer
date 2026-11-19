# 🌐 Azamat Traffic Analyzer

Tarmoq trafigini tahlil qilish, shubhali harakatlarni (C2 botnet, ma'lumot sizib chiqishi, virus yuklanishi) aniqlash hamda xavflarni vizual ko'rsatish uchun ishlab chiqilgan veb-platforma.

---

## 📌 Asosiy Imkoniyatlar

1. **PCAP va Log Tahlili**:
   - `.pcap`, `.pcapng`, `.cap` va `.log` formatdagi fayllarni chuqur tahlil qilish.
   - MITRE ATT&CK taktikalari asosida shubhali portlar, buyruqlar va ulanishlarni topish.
2. **Kiber Xarita va Interaktiv Graf**:
   - Tarmoqdagi barcha IP manzillar, ularning ulanish yo'llari va GeoIP joylashuvini xaritada (Leaflet) ko'rsatish.
   - Aloqa va paketlar hajmini interaktiv ko'rinishda taqdim etish.
3. **Tahdidlarni Aniqlash (Threat Intelligence)**:
   - DGA (Domain Generation Algorithms) va DNS orqali ma'lumot o'g'irlash (DNS Exfiltration - T1048.003).
   - Masofaviy boshqaruv (Reverse Shell - T1059) buyruqlari.
   - Bajariluvchi zararli fayllar (EXE, DLL, PowerShell skriptlari - T1105).
   - Rejalashtirilgan takroriy ulanishlar (Beaconing - T1132).
4. **Zararli Fayllarni Avtomatik Ajratib Olish (File Extraction)**:
   - Tarmoq trafigi orqali o'tayotgan EXE (MZ sarlavhali) fayllarni avtomatik tarzda `extracted_files/` jildiga ajratib saqlash.
5. **Ochiq Matndagi Parollarni Tutish**:
   - Shifrlanmagan HTTP oqimidan login va parollarni aniqlash.
6. **Xavfli Trafikni Alohida Yuklab Olish**:
   - Faqat xavfli paketlarni ajratib, alohida `.pcap` fayl sifatida saqlash.
7. **Windows Firewall Integratsiyasi**:
   - Aniqlangan xakerlik IP manzillarini bitta tugma orqali Windows Firewall tizimida bloklash va blokdan chiqarish.
8. **Jonli Tinglash (Live Sniffing)**:
   - Tarmoq kartasidan real vaqt rejimida paketlarni tutib tahlil qilish.

---

## 📂 Loyiha Tuzilishi

```text
├── app.py                 # Flask server va API yo'nalishlari
├── parser.py              # Scapy orqali paketlarni tahlil qilish mexanizmi
├── requirements.txt       # Kerakli Python kutubxonalari
├── .gitignore             # Git uchun chiqarib tashlanadigan fayllar
├── samples/               # Sinov uchun namunaviy fayllar (.pcap va .log)
│   ├── dns_exfil.pcap
│   └── sample.log
├── static/
│   ├── css/               # Dizayn uslublari (dark mode, glassmorphism)
│   └── js/                # Interaktiv xarita va grafiklar skripti
├── templates/
│   └── index.html         # Asosiy boshqaruv paneli (Dashboard)
├── uploads/               # Vaqtinchalik tahlil fayllari
└── extracted_files/       # Trafikdan ajratib olingan zararli fayllar
```

---

## 🚀 O'rnatish va Ishga Tushirish

### 1. Talablar
- Python 3.9 yoki undan yuqori versiya
- Windows operatsion tizimi (Firewall bloklash va Live Sniffing uchun tavsiya etiladi)
- Jonli tinglash uchun: [Npcap](https://npcap.com/) drayveri o'rnatilgan bo'lishi lozim

### 2. Loyihani yuklab olish
```bash
git clone https://github.com/USERNAME/REPO_NAME.git
cd REPO_NAME
```

### 3. Virtual muhit yaratish va faollashtirish
```bash
python -m venv venv
# Windows uchun:
.\venv\Scripts\activate
# Linux/macOS uchun:
source venv/bin/activate
```

### 4. Kerakli kutubxonalarni o'rnatish
```bash
pip install -r requirements.txt
```

### 5. Dasturni ishga tushirish
```bash
python app.py
```

Brauzerda quyidagi manzilni oching:
```
http://127.0.0.1:5000
```

> **Eslatma**: Agar Windows Firewall orqali IP manzillarni bloklash imkoniyatidan to'liq foydalanmoqchi bo'lsangiz, buyruqlar satrini (Terminal/PowerShell) **Administrator** sifatida oching.

---

## 🧪 Sinovdan O'tkazish

1. **Demo rejimi**: Sayt bosh sahifasidagi **Demo (Test) Yuklash** tugmasini bosib, dastur interfeysi qanday ishlashini ko'rishingiz mumkin.
2. **Namuna fayllar**: `samples/` jildida joylashgan `dns_exfil.pcap` yoki `sample.log` fayllarini yuklab tahlil qiling.
