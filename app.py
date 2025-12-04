import logging
import datetime
import firebase_admin
from firebase_admin import credentials, firestore
from flask import Flask, render_template, request, redirect, url_for, session, flash
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash, check_password_hash # Güvenli şifreleme için

# --- AYARLAR ---
logging.basicConfig(filename='app.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
app.secret_key = "cok_gizli_oturum_anahtari"

# Firebase Bağlantısı
if not firebase_admin._apps:
    cred = credentials.Certificate("serviceAccountKey.json")
    firebase_admin.initialize_app(cred)
db = firestore.client()

# Mesaj Şifreleme Anahtarı
ANAHTAR = b'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v=' 
cipher = Fernet(ANAHTAR)

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    try:
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return "[Şifre Çözülemedi]"

# --- ROTALAR ---

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

# KAYIT OLMA FONKSİYONU (YENİ)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # 1. Kullanıcı zaten var mı sorgula (Database Query)
        users_ref = db.collection('users').where('username', '==', username).stream()
        if len(list(users_ref)) > 0:
            flash('Bu kullanıcı adı zaten alınmış!', 'error')
            return redirect(url_for('register'))

        # 2. Şifreyi Hashle (Güvenlik Önlemi)
        hashed_password = generate_password_hash(password)

        # 3. Veritabanına Kaydet
        db.collection('users').add({
            'username': username,
            'password': hashed_password, # Asla gerçek şifreyi kaydetmiyoruz!
            'created_at': datetime.datetime.now()
        })

        flash('Kayıt başarılı! Lütfen giriş yapın.', 'success')
        return redirect(url_for('index'))
    
    return render_template('register.html')

# GİRİŞ YAPMA FONKSİYONU (GÜNCELLENDİ)
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    # 1. Veritabanında Kullanıcıyı Bul (Database Query)
    users_ref = db.collection('users').where('username', '==', username).stream()
    user_doc = None
    for doc in users_ref:
        user_doc = doc.to_dict()
        break

    # 2. Kullanıcı varsa ve şifre doğruysa
    if user_doc and check_password_hash(user_doc['password'], password):
        session['username'] = username
        logging.info(f"Giris basarili: {username}")
        return redirect(url_for('dashboard'))
    else:
        flash('Kullanıcı adı veya şifre hatalı!', 'error')
        logging.warning(f"Hatali giris denemesi: {username}")
        return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('index'))
    
    user = session['username']
    
    # Gelen Mesajları Çek
    gelen_mesajlar_ref = db.collection('messages').where('alici', '==', user).stream()
    
    mesaj_listesi = []
    for doc in gelen_mesajlar_ref:
        veri = doc.to_dict()
        mesaj_listesi.append({
            'gonderen': veri['gonderen'],
            'icerik': decrypt_data(veri['sifreli_icerik']),
            'tarih': veri['tarih']
        })
        
    return render_template('dashboard.html', username=user, mesajlar=mesaj_listesi)

@app.route('/send', methods=['POST'])
def send_message():
    if 'username' not in session:
        return redirect(url_for('index'))

    gonderen = session['username']
    alici = request.form['alici']
    acik_mesaj = request.form['mesaj']
    
    sifreli_mesaj = encrypt_data(acik_mesaj)
    
    db.collection('messages').add({
        'gonderen': gonderen,
        'alici': alici,
        'sifreli_icerik': sifreli_mesaj,
        'tarih': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })
    
    flash('Mesaj güvenle gönderildi.', 'success')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)