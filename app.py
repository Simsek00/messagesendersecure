"""
Secure Message System - Flask Backend
Proje: Güvenli Mesajlaşma Sistemi (Secure Coding & Scripting Languages)
Ekip: Mustafa Özcan, Mehmet Okur, Mehmet Arhan Efe, Türkay Aydoğan
"""

import os
import re
import logging
from flask import Flask, render_template, request, redirect, url_for, session, flash
import firebase_admin
from firebase_admin import credentials, firestore
from google.cloud.firestore import SERVER_TIMESTAMP
import bcrypt
from cryptography.fernet import Fernet

# ============= FLASK UYGULAMASI =============
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'development-secret-key-change-in-production')

# ============= LOGGING =============
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# ============= FIREBASE BAŞLATMA =============
try:
    if not firebase_admin._apps:
        cred = credentials.Certificate("serviceAccountKey.json")
        firebase_admin.initialize_app(cred)
    db = firestore.client()
    print("✓ Firebase/Firestore bağlantısı başarılı")
    logging.info("Firebase baglantisi basarili")
except Exception as e:
    print(f"✗ Firebase başlatma hatası: {e}")
    logging.error(f"Firebase hata: {e}")
    raise

# ============= ŞİFRELEME ANAHTARI =============
# Production'da environment variable kullanılmalı!
ENCRYPTION_KEY = b'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v='
cipher_suite = Fernet(ENCRYPTION_KEY)

# ============= GÜVENLİK FONKSİYONLARI =============

def hash_password(password: str) -> str:
    """Bcrypt ile şifre hashleme (Secure Coding requirement)"""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """Hashlenmiş şifreyi doğrula"""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except Exception as e:
        logging.error(f"Password verification error: {e}")
        return False

def encrypt_message(text: str) -> str:
    """Mesajı Fernet (AES) ile şifrele"""
    return cipher_suite.encrypt(text.encode()).decode()

def decrypt_message(encrypted_text: str) -> str:
    """Şifreli mesajı çöz"""
    try:
        return cipher_suite.decrypt(encrypted_text.encode()).decode()
    except Exception as e:
        logging.error(f"Decryption error: {e}")
        return "[Şifre çözülemedi]"

# ============= INPUT VALIDATION =============

def validate_username(username: str) -> tuple:
    """
    Kullanıcı adı validasyonu (XSS/Injection koruması)
    Returns: (is_valid: bool, message: str)
    """
    if not username:
        return False, "Kullanıcı adı boş olamaz"
    
    username = username.strip()
    
    if len(username) < 3:
        return False, "Kullanıcı adı en az 3 karakter olmalı"
    
    if len(username) > 20:
        return False, "Kullanıcı adı en fazla 20 karakter olabilir"
    
    # Sadece harf, rakam ve alt çizgi
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Kullanıcı adı sadece harf, rakam ve _ içerebilir"
    
    return True, username.strip()

def validate_password(password: str) -> tuple:
    """
    Şifre validasyonu
    Returns: (is_valid: bool, message: str)
    """
    if not password:
        return False, "Şifre boş olamaz"
    
    if len(password) < 6:
        return False, "Şifre en az 6 karakter olmalı"
    
    if len(password) > 128:
        return False, "Şifre çok uzun"
    
    return True, "OK"

def validate_message(message: str) -> tuple:
    """
    Mesaj içeriği validasyonu
    Returns: (is_valid: bool, message: str)
    """
    if not message or not message.strip():
        return False, "Mesaj boş olamaz"
    
    if len(message) > 5000:
        return False, "Mesaj çok uzun (max 5000 karakter)"
    
    return True, message.strip()

# ============= FLASK ROUTES =============

@app.route('/')
def index():
    """Ana sayfa - Login veya Dashboard'a yönlendir"""
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Kullanıcı kaydı"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # Input validation
        is_valid_user, msg_user = validate_username(username)
        if not is_valid_user:
            flash(msg_user, 'error')
            return redirect(url_for('register'))
        
        username = msg_user  # Sanitized username
        
        is_valid_pass, msg_pass = validate_password(password)
        if not is_valid_pass:
            flash(msg_pass, 'error')
            return redirect(url_for('register'))
        
        try:
            # Kullanıcı zaten var mı kontrol et
            from google.cloud.firestore_v1.base_query import FieldFilter
            users_ref = db.collection('users')
            existing_user = users_ref.where(
                filter=FieldFilter('username', '==', username)
            ).limit(1).get()
            
            if len(existing_user) > 0:
                flash('Bu kullanıcı adı zaten kullanılıyor!', 'error')
                logging.warning(f"Kayit denemesi - kullanici var: {username}")
                return redirect(url_for('register'))
            
            # Şifreyi hashle
            hashed_password = hash_password(password)
            
            # Veritabanına kaydet
            users_ref.add({
                'username': username,
                'password': hashed_password,
                'created_at': SERVER_TIMESTAMP
            })
            
            flash('Kayıt başarılı! Giriş yapabilirsiniz.', 'success')
            logging.info(f"Yeni kullanici kaydi: {username}")
            return redirect(url_for('index'))
            
        except Exception as e:
            flash(f'Bir hata oluştu: {str(e)}', 'error')
            logging.error(f"Register error: {e}")
            return redirect(url_for('register'))
    
    return render_template('register.html')

@app.route('/login', methods=['POST'])
def login():
    """Kullanıcı girişi"""
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    
    # Input validation
    is_valid_user, msg_user = validate_username(username)
    if not is_valid_user:
        flash('Geçersiz kullanıcı adı!', 'error')
        return redirect(url_for('index'))
    
    username = msg_user  # Sanitized username
    
    try:
        # Kullanıcıyı bul
        from google.cloud.firestore_v1.base_query import FieldFilter
        users_ref = db.collection('users')
        user_docs = users_ref.where(
            filter=FieldFilter('username', '==', username)
        ).limit(1).get()
        
        if not user_docs:
            flash('Kullanıcı adı veya şifre hatalı!', 'error')
            logging.warning(f"Basarisiz giris: {username}")
            return redirect(url_for('index'))
        
        user_data = user_docs[0].to_dict()
        
        # Şifre kontrolü
        if verify_password(password, user_data['password']):
            session['username'] = username
            logging.info(f"Basarili giris: {username}")
            return redirect(url_for('dashboard'))
        else:
            flash('Kullanıcı adı veya şifre hatalı!', 'error')
            logging.warning(f"Basarisiz giris (yanlis sifre): {username}")
            return redirect(url_for('index'))
            
    except Exception as e:
        flash(f'Giriş hatası: {str(e)}', 'error')
        logging.error(f"Login error: {e}")
        return redirect(url_for('index'))

@app.route('/logout')
def logout():
    """Çıkış yap"""
    username = session.get('username', 'Bilinmeyen')
    session.pop('username', None)
    logging.info(f"Cikis: {username}")
    flash('Çıkış yapıldı.', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    """Ana panel - mesajları göster"""
    if 'username' not in session:
        return redirect(url_for('index'))
    
    username = session['username']
    
    try:
        # Gelen mesajları çek (order_by kaldırıldı - Firestore index gerektiriyor)
        from google.cloud.firestore_v1.base_query import FieldFilter
        messages_ref = db.collection('messages')
        incoming_messages = messages_ref.where(
            filter=FieldFilter('receiver', '==', username)
        ).limit(50).get()
        
        messages = []
        for doc in incoming_messages:
            msg_data = doc.to_dict()
            # Timestamp'i düzgün formatla
            timestamp = msg_data.get('timestamp')
            if timestamp:
                timestamp_str = timestamp.strftime("%d.%m.%Y %H:%M")
            else:
                timestamp_str = "Tarih yok"
            
            messages.append({
                'sender': msg_data.get('sender', 'Bilinmeyen'),
                'content': decrypt_message(msg_data.get('encrypted_content', '')),
                'timestamp': timestamp_str
            })
        
        return render_template('dashboard.html', username=username, messages=messages)
        
    except Exception as e:
        flash(f'Mesajlar yüklenemedi: {str(e)}', 'error')
        logging.error(f"Dashboard error: {e}")
        return render_template('dashboard.html', username=username, messages=[])

@app.route('/send', methods=['POST'])
def send_message():
    """Mesaj gönder"""
    if 'username' not in session:
        return redirect(url_for('index'))
    
    sender = session['username']
    receiver = request.form.get('receiver', '').strip()
    message_content = request.form.get('message', '').strip()
    
    # Input validation
    is_valid_receiver, msg_receiver = validate_username(receiver)
    if not is_valid_receiver:
        flash(f'Geçersiz alıcı: {msg_receiver}', 'error')
        return redirect(url_for('dashboard'))
    
    receiver = msg_receiver  # Sanitized
    
    is_valid_msg, msg_validated = validate_message(message_content)
    if not is_valid_msg:
        flash(msg_validated, 'error')
        return redirect(url_for('dashboard'))
    
    message_content = msg_validated  # Sanitized
    
    try:
        # Mesajı şifrele
        encrypted_content = encrypt_message(message_content)
        
        # Veritabanına kaydet
        db.collection('messages').add({
            'sender': sender,
            'receiver': receiver,
            'encrypted_content': encrypted_content,
            'timestamp': SERVER_TIMESTAMP
        })
        
        flash(f'Mesaj {receiver} kullanıcısına güvenle gönderildi!', 'success')
        logging.info(f"Mesaj gonderildi: {sender} -> {receiver}")
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        flash(f'Mesaj gönderilemedi: {str(e)}', 'error')
        logging.error(f"Send message error: {e}")
        return redirect(url_for('dashboard'))

# ============= UYGULAMA BAŞLATMA =============

if __name__ == '__main__':
    print("=" * 50)
    print("SECURE MESSAGE SYSTEM")
    print("=" * 50)
    print("Güvenli mesajlaşma sistemi başlatılıyor...")
    print("Tarayıcıdan http://127.0.0.1:5000 adresine gidin")
    print("=" * 50)
    app.run(debug=True, host='0.0.0.0', port=5000)

