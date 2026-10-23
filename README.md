# Secure Message System

**[English](#english) | [Türkçe](#türkçe)**

---

## English

**Secure Messaging System** - Scripting Languages & Secure Coding Course Project

### 📋 About the Project

This project is a messaging system with server-side encryption. Message contents are encrypted with Fernet (AES) before they are written to the database, so the database (Firestore) and its backups only see ciphertext. Passwords are hashed with bcrypt.

> ℹ️ This is **not** end-to-end encryption: all messages are encrypted with a single key held by the server (`ENCRYPTION_KEY`). Anyone with access to the server or the `.env` file can decrypt them.

#### 🎯 Project Goals

1. **Secure Authentication:** Password hashing with bcrypt
2. **Encrypted Messaging:** Message encryption with Fernet (AES-256)
3. **Input Validation:** Protection against XSS and injection attacks
4. **Logging:** Audit log of all operations
5. **CSRF Protection:** Every POST form and request carries a token (Flask-WTF); logout is POST-only
6. **Rate Limiting:** Login (5/min, 20/hour) and registration (10/hour) per IP (Flask-Limiter)
7. **Session Security:** HttpOnly + SameSite cookies, 1-hour session lifetime

### 👥 Team

- **Mustafa Özcan:** Backend Development (Authentication & Input Validation)
- **Mehmet Okur:** Encryption Algorithms & Secure Storage
- **Mehmet Arhan Efe:** Frontend UI & Flask Routes
- **Türkay Aydoğan:** Automation Scripts

### 🚀 Installation and Running

> This repository contains no secret keys. Anyone who downloads the project must create their own Firebase project and their own keys. Example files: `.env.example`, `serviceAccountKey.example.json`.

#### 1. Requirements
- Python 3.10+
- A free [Firebase](https://console.firebase.google.com/) account

#### 2. Clone the project and install dependencies
```bash
git clone https://github.com/Simsek00/messagesendersecure.git
cd messagesendersecure
python -m venv .venv
```
Activate the virtual environment:
- Windows: `.venv\Scripts\activate`
- macOS / Linux: `source .venv/bin/activate`

```bash
pip install -r requirements.txt
```

#### 3. Set up Firebase
1. Create a new project in the [Firebase Console](https://console.firebase.google.com/).
2. Create a Firestore database under **Build → Firestore Database**. The app creates the `users` and `messages` collections itself.
3. Download the service account JSON file via **Project settings → Service accounts → Generate new private key**.
4. Put the downloaded file in the project root as **`serviceAccountKey.json`**. The expected structure is shown in `serviceAccountKey.example.json`.

> ⚠️ `serviceAccountKey.json` gives full access to your database. The file is in `.gitignore`; never commit or share it.

#### 4. Create the `.env` file
Copy `.env.example` to `.env`:
```bash
cp .env.example .env        # macOS / Linux
copy .env.example .env      # Windows (cmd)
```
Then generate the two keys and paste them into `.env`:
```bash
# SECRET_KEY (Flask session key)
python -c "import secrets; print(secrets.token_hex(32))"

# ENCRYPTION_KEY (Fernet / AES message encryption key)
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

> ⚠️ If `ENCRYPTION_KEY` changes, previously encrypted messages can no longer be decrypted. Keep the key somewhere safe.

#### 5. Run the app
```bash
python app.py
```
Open `http://localhost:5000` in your browser.

By default the server only listens on `127.0.0.1` with debug mode off. For development you can set `FLASK_DEBUG=1` in `.env` (only together with `FLASK_HOST=127.0.0.1`, since the debugger allows remote code execution). The other settings are documented in `.env.example`.

#### 6. Run the tests
The tests mock Firebase and use test keys, so they run without `.env` or `serviceAccountKey.json` and never touch your real database.
```bash
pytest
```
To run a specific category (markers in `pytest.ini`) or get a coverage report:
```bash
pytest -m security
pytest -m crypto
pytest --cov=app --cov-report=term-missing
```

#### 7. (Optional) Automatic backup
`backup.py` backs up the `messages` collection to a `backup_YYYYMMDD_HHMM.json` file. These files are also in `.gitignore`. The script currently runs once and exits. To take a backup automatically every day, uncomment the `schedule` lines at the end of the file.
```bash
python backup.py
```

### 📚 Resources

- [Flask Documentation](https://flask.palletsprojects.com/)
- [Firebase Firestore Docs](https://firebase.google.com/docs/firestore)
- [bcrypt Docs](https://github.com/pyca/bcrypt/)
- [cryptography Docs](https://cryptography.io/)

**🔒 Security is our priority!**

---

## Türkçe

**Güvenli Mesajlaşma Sistemi** - Scripting Languages & Secure Coding Dersi Projesi

### 📋 Proje Hakkında

Bu proje, sunucu tarafında şifreleme yapan bir mesajlaşma sistemidir. Mesaj içerikleri veritabanına yazılmadan önce Fernet (AES) ile şifrelenir; bu yüzden veritabanı (Firestore) ve yedekleri sadece şifreli metni görür. Şifreler bcrypt ile hashlenir.

> ℹ️ Bu **uçtan uca (end-to-end) şifreleme değildir**: tüm mesajlar sunucuda tutulan tek bir anahtarla (`ENCRYPTION_KEY`) şifrelenir. Sunucuya veya `.env` dosyasına erişen biri mesajları çözebilir.

#### 🎯 Proje Hedefleri

1. **Secure Authentication:** Manuel bcrypt ile password hashing
2. **Encrypted Messaging:** Fernet (AES-256) ile mesaj şifreleme
3. **Input Validation:** XSS ve Injection saldırılarına karşı koruma
4. **Logging:** Tüm işlemlerin audit log'u
5. **CSRF Koruması:** Tüm POST formları ve istekleri token taşır (Flask-WTF); çıkış sadece POST ile yapılır
6. **Rate Limiting:** IP başına giriş (5/dakika, 20/saat) ve kayıt (10/saat) sınırı (Flask-Limiter)
7. **Oturum Güvenliği:** HttpOnly + SameSite cookie, 1 saatlik oturum süresi

### 👥 Ekip

- **Mustafa Özcan:** Backend Development (Authentication & Input Validation)
- **Mehmet Okur:** Encryption Algorithms & Secure Storage
- **Mehmet Arhan Efe:** Frontend UI & Flask Routes
- **Türkay Aydoğan:** Automation Scripts

### 🚀 Kurulum ve Çalıştırma

> Bu repoda hiçbir gizli anahtar yoktur. Projeyi indiren herkes kendi Firebase projesini ve kendi anahtarlarını oluşturmalıdır. Örnek dosyalar: `.env.example`, `serviceAccountKey.example.json`.

#### 1. Gereksinimler
- Python 3.10+
- Ücretsiz bir [Firebase](https://console.firebase.google.com/) hesabı

#### 2. Projeyi indirin ve bağımlılıkları kurun
```bash
git clone https://github.com/Simsek00/messagesendersecure.git
cd messagesendersecure
python -m venv .venv
```
Sanal ortamı etkinleştirin:
- Windows: `.venv\Scripts\activate`
- macOS / Linux: `source .venv/bin/activate`

```bash
pip install -r requirements.txt
```

#### 3. Firebase'i ayarlayın
1. [Firebase Console](https://console.firebase.google.com/) üzerinden yeni bir proje oluşturun.
2. **Build → Firestore Database** menüsünden bir Firestore veritabanı oluşturun. Uygulama `users` ve `messages` koleksiyonlarını kendisi oluşturur.
3. **Project settings → Service accounts → Generate new private key** ile service account JSON dosyasını indirin.
4. İndirdiğiniz dosyayı proje kök dizinine **`serviceAccountKey.json`** adıyla koyun. Dosyanın beklenen yapısı `serviceAccountKey.example.json` içinde görülebilir.

> ⚠️ `serviceAccountKey.json` veritabanınıza tam erişim verir. Dosya `.gitignore`'dadır; asla commit'lemeyin veya paylaşmayın.

#### 4. `.env` dosyasını oluşturun
`.env.example` dosyasını `.env` adıyla kopyalayın:
```bash
cp .env.example .env        # macOS / Linux
copy .env.example .env      # Windows (cmd)
```
Ardından iki anahtarı üretip `.env` içine yapıştırın:
```bash
# SECRET_KEY (Flask session anahtarı)
python -c "import secrets; print(secrets.token_hex(32))"

# ENCRYPTION_KEY (Fernet / AES mesaj şifreleme anahtarı)
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

> ⚠️ `ENCRYPTION_KEY` değişirse daha önce şifrelenmiş mesajlar çözülemez. Anahtarı güvenli bir yerde saklayın.

#### 5. Uygulamayı çalıştırın
```bash
python app.py
```
Tarayıcıdan `http://localhost:5000` adresine gidin.

Sunucu varsayılan olarak sadece `127.0.0.1` adresini dinler ve debug modu kapalıdır. Geliştirirken `.env`'de `FLASK_DEBUG=1` yapabilirsiniz (debugger uzaktan kod çalıştırmaya izin verdiği için sadece `FLASK_HOST=127.0.0.1` ile birlikte). Diğer ayarlar `.env.example` içinde açıklanmıştır.

#### 6. Testleri çalıştırın
Testler Firebase'i mock'lar ve test anahtarları kullanır; bu yüzden `.env` veya `serviceAccountKey.json` olmadan çalışır ve gerçek veritabanınıza dokunmaz.
```bash
pytest
```
Belirli bir kategoriyi çalıştırmak (`pytest.ini` içindeki marker'lar) ve coverage raporu almak için:
```bash
pytest -m security
pytest -m crypto
pytest --cov=app --cov-report=term-missing
```

#### 7. (İsteğe bağlı) Otomatik yedekleme
`backup.py`, `messages` koleksiyonunu `backup_YYYYMMDD_HHMM.json` dosyasına yedekler. Bu dosyalar da `.gitignore`'dadır. Script şu an bir kez çalışıp çıkar. Her gün otomatik yedek almak için dosyanın sonundaki `schedule` satırlarını açabilirsiniz.
```bash
python backup.py
```

### 📚 Kaynaklar

- [Flask Documentation](https://flask.palletsprojects.com/)
- [Firebase Firestore Docs](https://firebase.google.com/docs/firestore)
- [bcrypt Docs](https://github.com/pyca/bcrypt/)
- [cryptography Docs](https://cryptography.io/)

**🔒 Güvenlik önceliğimizdir!**
