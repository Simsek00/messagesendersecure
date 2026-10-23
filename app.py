import os
import re
import logging
from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import firebase_admin
from firebase_admin import credentials, firestore
from google.cloud.firestore import SERVER_TIMESTAMP
import bcrypt
from cryptography.fernet import Fernet
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# ============= ENVIRONMENT VARIABLES CHECK =============
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    raise ValueError(
        "CRITICAL: SECRET_KEY environment variable is not set!\n"
        "Please create a .env file with SECRET_KEY."
    )

ENCRYPTION_KEY_STR = os.environ.get('ENCRYPTION_KEY')
if not ENCRYPTION_KEY_STR:
    raise ValueError(
        "CRITICAL: ENCRYPTION_KEY environment variable is not set!\n"
        "Please create a .env file with ENCRYPTION_KEY."
    )

# ============= FLASK UYGULAMASI =============
app = Flask(__name__)
app.secret_key = SECRET_KEY

# ============= SESSION COOKIE AYARLARI =============
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,      # JavaScript session cookie'sini okuyamaz
    SESSION_COOKIE_SAMESITE='Lax',     # Başka sitelerden gelen POST isteklerinde cookie gönderilmez
    # HTTPS arkasında yayınlarken .env'de SESSION_COOKIE_SECURE=1 yapın (cookie sadece HTTPS'te gönderilir)
    SESSION_COOKIE_SECURE=os.environ.get('SESSION_COOKIE_SECURE', '0').lower() in ('1', 'true', 'yes'),
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1),  # Oturum 1 saat sonra sona erer
)

# ============= CSRF KORUMASI =============
# Tüm POST istekleri session'a bağlı bir token ister: formlarda gizli csrf_token alanı,
# fetch isteklerinde X-CSRFToken header'ı. Başka bir siteden gönderilen sahte formlar reddedilir.
csrf = CSRFProtect(app)

# ============= RATE LIMITING =============
# Kaba kuvvet (brute force) şifre denemelerine karşı giriş ve kayıt istekleri IP başına sınırlanır.
# memory:// sayaçları bu sürecin belleğinde tutar; birden fazla sunucu sürecinde Redis gibi ortak bir depo kullanılmalı.
limiter = Limiter(get_remote_address, app=app, storage_uri="memory://")

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
    logging.info("Firebase baglantisi basarili")
except Exception as e:
    print(f"Firebase başlatma hatası: {e}")
    logging.error(f"Firebase hata: {e}")
    raise

# ============= ŞİFRELEME ANAHTARI =============
# Encode encryption key (already validated above)
try:
    ENCRYPTION_KEY = ENCRYPTION_KEY_STR.encode('utf-8')
    cipher_suite = Fernet(ENCRYPTION_KEY)
except Exception as e:
    raise ValueError(f"CRITICAL: Invalid ENCRYPTION_KEY format: {e}")

# Hata ayrıntıları (exception metni) kullanıcıya gösterilmez, sadece app.log'a yazılır:
# veritabanı yapısı, dosya yolları gibi iç bilgilerin sızmasını önler.

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
    
    # bcrypt en fazla 72 byte işler; bcrypt 5.x daha uzun şifrede hata fırlatır.
    # Türkçe karakterler (ç, ğ, ı, ö, ş, ü) UTF-8'de 2 byte olduğu için karakter değil byte sayılır.
    if len(password.encode('utf-8')) > 72:
        return False, "Şifre çok uzun (en fazla 72 byte; Türkçe karakterler 2 byte sayılır)"

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
@limiter.limit("10 per hour", methods=['POST'])
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
            flash('Kayıt sırasında bir hata oluştu. Lütfen daha sonra tekrar deneyin.', 'error')
            logging.error(f"Register error: {e}")
            return redirect(url_for('register'))
    
    return render_template('register.html')

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute;20 per hour")
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
            # Önceki oturumdan kalan veriyi temizle, süreli oturum başlat
            session.clear()
            session.permanent = True
            session['username'] = username
            logging.info(f"Basarili giris: {username}")
            return redirect(url_for('dashboard'))
        else:
            flash('Kullanıcı adı veya şifre hatalı!', 'error')
            logging.warning(f"Basarisiz giris (yanlis sifre): {username}")
            return redirect(url_for('index'))
            
    except Exception as e:
        flash('Giriş sırasında bir hata oluştu. Lütfen daha sonra tekrar deneyin.', 'error')
        logging.error(f"Login error: {e}")
        return redirect(url_for('index'))

@app.route('/logout', methods=['POST'])
def logout():
    """Çıkış yap (POST: başka bir site kullanıcıyı GET linkiyle çıkışa zorlayamaz)"""
    username = session.get('username', 'Bilinmeyen')
    session.pop('username', None)
    logging.info(f"Cikis: {username}")
    flash('Çıkış yapıldı.', 'success')
    return redirect(url_for('index'))

@app.errorhandler(429)
def handle_rate_limit(e):
    """Çok fazla deneme (rate limit aşıldı)"""
    logging.warning(f"Rate limit asildi: {get_remote_address()} {request.path}")
    flash('Çok fazla deneme yaptınız. Lütfen biraz bekleyip tekrar deneyin.', 'error')
    return redirect(url_for('index')), 302

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    """Geçersiz veya eksik CSRF token'ı"""
    logging.warning(f"CSRF hatasi: {request.path} - {e.description}")
    if request.is_json or request.path.startswith('/delete_message/'):
        return jsonify({'success': False, 'error': 'Oturum doğrulanamadı, sayfayı yenileyin'}), 400
    flash('Oturum doğrulanamadı. Lütfen sayfayı yenileyip tekrar deneyin.', 'error')
    return redirect(url_for('index'))

DASHBOARD_MESSAGE_LIMIT = 50

def _timestamp_sort_key(timestamp) -> float:
    """Sıralama anahtarı: datetime'ı sayıya çevirir; tarihi olmayan mesaj 0 olur (datetime ile 0 karşılaştırılamaz)"""
    return timestamp.timestamp() if timestamp else 0.0

@app.route('/dashboard')
def dashboard():
    """Ana panel - mesajları göster"""
    if 'username' not in session:
        return redirect(url_for('index'))
    
    username = session['username']
    
    try:
        from google.cloud.firestore_v1.base_query import FieldFilter
        messages_ref = db.collection('messages')
        # limit() sıralamadan önce uygulanırsa Firestore rastgele 50 mesaj döndürür ve en yeniler görünmeyebilir.
        # order_by + where farklı alanlarda composite index gerektirdiği için sıralama Python'da yapılır.
        incoming_docs = [(doc.id, doc.to_dict()) for doc in messages_ref.where(
            filter=FieldFilter('receiver', '==', username)
        ).get()]

        # Mesajları tarihe göre sırala (en yeniden eskiye); tarihi olmayanlar en sona
        incoming_docs.sort(key=lambda item: _timestamp_sort_key(item[1].get('timestamp')), reverse=True)

        messages = []
        for doc_id, msg_data in incoming_docs[:DASHBOARD_MESSAGE_LIMIT]:
            # Timestamp'i düzgün formatla
            timestamp = msg_data.get('timestamp')
            timestamp_str = timestamp.strftime("%d.%m.%Y %H:%M") if timestamp else "Tarih yok"

            messages.append({
                'id': doc_id,  # Mesaj ID'si (silme için gerekli)
                'sender': msg_data.get('sender', 'Bilinmeyen'),
                'content': decrypt_message(msg_data.get('encrypted_content', '')),
                'timestamp': timestamp_str
            })

        return render_template('dashboard.html', username=username, messages=messages)
        
    except Exception as e:
        flash('Mesajlar yüklenemedi. Lütfen daha sonra tekrar deneyin.', 'error')
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
        # Alıcı kayıtlı olmalı; aksi halde mesaj, ileride bu adla kayıt olan birine gider
        from google.cloud.firestore_v1.base_query import FieldFilter
        receiver_docs = db.collection('users').where(
            filter=FieldFilter('username', '==', receiver)
        ).limit(1).get()

        if len(receiver_docs) == 0:
            flash(f'"{receiver}" adında bir kullanıcı bulunamadı.', 'error')
            logging.warning(f"Olmayan aliciya mesaj denemesi: {sender} -> {receiver}")
            return redirect(url_for('dashboard'))

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
        flash('Mesaj gönderilemedi. Lütfen daha sonra tekrar deneyin.', 'error')
        logging.error(f"Send message error: {e}")
        return redirect(url_for('dashboard'))

@app.route('/delete_message/<message_id>', methods=['POST'])
def delete_message(message_id):
    """Mesaj sil"""
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Oturum geçersiz'}), 401
    
    username = session['username']
    
    try:
        # Mesajı bul
        message_ref = db.collection('messages').document(message_id)
        message_doc = message_ref.get()
        
        if not message_doc.exists:
            return jsonify({'success': False, 'error': 'Mesaj bulunamadı'}), 404
        
        message_data = message_doc.to_dict()
        
        # Sadece alıcı kendi mesajlarını silebilir (güvenlik kontrolü)
        if message_data.get('receiver') != username:
            logging.warning(f"Yetkisiz silme denemesi: {username} -> {message_id}")
            return jsonify({'success': False, 'error': 'Bu mesajı silme yetkiniz yok'}), 403
        
        # Mesajı sil
        message_ref.delete()
        
        logging.info(f"Mesaj silindi: {username} -> {message_id}")
        return jsonify({'success': True, 'message': 'Mesaj başarıyla silindi'})
        
    except Exception as e:
        logging.error(f"Delete message error: {e}")
        return jsonify({'success': False, 'error': 'Mesaj silinemedi, lütfen tekrar deneyin'}), 500

@app.route('/profile')
def profile():
    """Kullanıcı profil sayfası"""
    if 'username' not in session:
        return redirect(url_for('index'))
    
    username = session['username']
    
    try:
        # Kullanıcı bilgilerini çek
        from google.cloud.firestore_v1.base_query import FieldFilter
        users_ref = db.collection('users')
        user_docs = users_ref.where(
            filter=FieldFilter('username', '==', username)
        ).limit(1).get()
        
        if not user_docs:
            flash('Kullanıcı bulunamadı!', 'error')
            return redirect(url_for('dashboard'))
        
        user_data = user_docs[0].to_dict()
        user_id = user_docs[0].id
        
        # Kayıt tarihini formatla
        created_at = user_data.get('created_at')
        if created_at:
            created_at_str = created_at.strftime("%d %B %Y, %H:%M")
        else:
            created_at_str = "Bilinmiyor"
        
        # Mesaj istatistiklerini çek
        sent_messages = db.collection('messages').where(
            filter=FieldFilter('sender', '==', username)
        ).get()
        
        received_messages = db.collection('messages').where(
            filter=FieldFilter('receiver', '==', username)
        ).get()
        
        profile_data = {
            'username': username,
            'user_id': user_id,
            'created_at': created_at_str,
            'sent_count': len(sent_messages),
            'received_count': len(received_messages)
        }
        
        return render_template('profile.html', user=profile_data)
        
    except Exception as e:
        flash('Profil yüklenemedi. Lütfen daha sonra tekrar deneyin.', 'error')
        logging.error(f"Profile error: {e}")
        return redirect(url_for('dashboard'))

@app.route('/change_password', methods=['POST'])
def change_password():
    """Şifre değiştir"""
    if 'username' not in session:
        return redirect(url_for('index'))
    
    username = session['username']
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')
    
    try:
        # Input validation
        is_valid_new, msg_new = validate_password(new_password)
        if not is_valid_new:
            flash(f'Yeni şifre geçersiz: {msg_new}', 'error')
            return redirect(url_for('profile'))
        
        if new_password != confirm_password:
            flash('Yeni şifreler eşleşmiyor!', 'error')
            return redirect(url_for('profile'))
        
        # Kullanıcıyı bul
        from google.cloud.firestore_v1.base_query import FieldFilter
        users_ref = db.collection('users')
        user_docs = users_ref.where(
            filter=FieldFilter('username', '==', username)
        ).limit(1).get()
        
        if not user_docs:
            flash('Kullanıcı bulunamadı!', 'error')
            return redirect(url_for('profile'))
        
        user_data = user_docs[0].to_dict()
        user_doc_ref = user_docs[0].reference
        
        # Mevcut şifreyi doğrula
        if not verify_password(current_password, user_data['password']):
            flash('Mevcut şifreniz yanlış!', 'error')
            logging.warning(f"Basarisiz sifre degistirme: {username}")
            return redirect(url_for('profile'))
        
        # Yeni şifreyi hashle ve güncelle
        new_hashed_password = hash_password(new_password)
        user_doc_ref.update({'password': new_hashed_password})
        
        flash('Şifreniz başarıyla değiştirildi!', 'success')
        logging.info(f"Sifre degistirildi: {username}")
        return redirect(url_for('profile'))
        
    except Exception as e:
        flash('Şifre değiştirilemedi. Lütfen daha sonra tekrar deneyin.', 'error')
        logging.error(f"Change password error: {e}")
        return redirect(url_for('profile'))

@app.route('/delete_account', methods=['POST'])
def delete_account():
    """Hesabı sil (opsiyonel özellik)"""
    if 'username' not in session:
        return redirect(url_for('index'))
    
    username = session['username']
    password = request.form.get('confirm_password', '')
    
    try:
        # Kullanıcıyı bul
        from google.cloud.firestore_v1.base_query import FieldFilter
        users_ref = db.collection('users')
        user_docs = users_ref.where(
            filter=FieldFilter('username', '==', username)
        ).limit(1).get()
        
        if not user_docs:
            flash('Kullanıcı bulunamadı!', 'error')
            return redirect(url_for('profile'))
        
        user_data = user_docs[0].to_dict()
        user_doc_ref = user_docs[0].reference
        
        # Şifre doğrulama (güvenlik için)
        if not verify_password(password, user_data['password']):
            flash('Şifre yanlış! Hesap silinmedi.', 'error')
            logging.warning(f"Basarisiz hesap silme denemesi: {username}")
            return redirect(url_for('profile'))
        
        # Kullanıcının tüm mesajlarını sil
        # Gönderilen mesajlar
        sent_messages = db.collection('messages').where(
            filter=FieldFilter('sender', '==', username)
        ).get()
        for msg in sent_messages:
            msg.reference.delete()
        
        # Alınan mesajlar
        received_messages = db.collection('messages').where(
            filter=FieldFilter('receiver', '==', username)
        ).get()
        for msg in received_messages:
            msg.reference.delete()
        
        # Kullanıcıyı sil
        user_doc_ref.delete()
        
        # Oturumu kapat
        session.pop('username', None)
        
        flash('Hesabınız ve tüm mesajlarınız başarıyla silindi.', 'success')
        logging.info(f"Hesap silindi: {username}")
        return redirect(url_for('index'))
        
    except Exception as e:
        flash('Hesap silinemedi. Lütfen daha sonra tekrar deneyin.', 'error')
        logging.error(f"Delete account error: {e}")
        return redirect(url_for('profile'))

# ============= UYGULAMA BAŞLATMA =============

if __name__ == '__main__':
    # Debug modu (Werkzeug debugger) varsayılan olarak KAPALI ve sunucu sadece bu bilgisayardan erişilebilir.
    # Debugger ağa açılırsa uzaktan kod çalıştırmaya izin verir; geliştirirken .env'de FLASK_DEBUG=1 yapın.
    debug = os.environ.get('FLASK_DEBUG', '0').lower() in ('1', 'true', 'yes')
    host = os.environ.get('FLASK_HOST', '127.0.0.1')
    port = int(os.environ.get('FLASK_PORT', '5000'))

    if debug and host not in ('127.0.0.1', 'localhost'):
        raise ValueError("CRITICAL: FLASK_DEBUG açıkken FLASK_HOST sadece 127.0.0.1 veya localhost olabilir.")

    print("=" * 50)
    print("SECURE MESSAGE SYSTEM")
    print("=" * 50)
    print("Güvenli mesajlaşma sistemi başlatılıyor...")
    print(f"Tarayıcıdan http://{'127.0.0.1' if host == '0.0.0.0' else host}:{port} adresine gidin")
    print("=" * 50)
    app.run(debug=debug, host=host, port=port)

