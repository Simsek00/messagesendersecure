"""
Pytest Configuration ve Fixtures
================================

Bu dosya pytest'in test öncesi hazırlıklarını yapar.

FIXTURE NEDİR?
--------------
Fixture: Test fonksiyonlarında kullanılacak hazır objeler/veriler.
Örneğin: Test kullanıcısı, Flask client, örnek mesaj vb.

@pytest.fixture decorator'ı ile tanımlanır.
Test fonksiyonları parametre olarak fixture adını alır.

ÖRNEK:
    @pytest.fixture
    def sample_user():
        return {'username': 'test', 'password': '123456'}
    
    def test_something(sample_user):  # fixture otomatik inject edilir
        assert sample_user['username'] == 'test'
"""
import pytest
import sys
import os
from datetime import datetime

# Ana dizini path'e ekle (app.py'yi import edebilmek için)
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# app.py'den gerekli fonksiyonları import et
from app import app as flask_app, hash_password


# ============= FLASK FIXTURES =============

@pytest.fixture
def app():
    """
    Flask app fixture (test mode)
    
    Ne İşe Yarar:
        Flask uygulamasını test modunda döndürür.
        TESTING=True ayarı, hata mesajlarını detaylı gösterir.
    
    Kullanım:
        def test_app_exists(app):
            assert app is not None
    """
    flask_app.config['TESTING'] = True
    flask_app.config['SECRET_KEY'] = 'test-secret-key-for-pytest'
    flask_app.config['WTF_CSRF_ENABLED'] = False
    
    yield flask_app


@pytest.fixture
def client(app):
    """
    Flask Test Client fixture
    
    Ne İşe Yarar:
        HTTP istekleri (GET, POST) simüle eder.
        Gerçek bir sunucu çalıştırmadan route'ları test eder.
    
    Kullanım:
        def test_homepage(client):
            response = client.get('/')
            assert response.status_code == 200
    """
    return app.test_client()


@pytest.fixture
def authenticated_client(client):
    """
    Oturum açmış kullanıcı ile test client
    
    Ne İşe Yarar:
        Session'a kullanıcı ekler, login gerektiren sayfaları test eder.
    
    Kullanım:
        def test_dashboard(authenticated_client):
            response = authenticated_client.get('/dashboard')
            # Login olmadan 302 alırdık, şimdi 200 alıyoruz
    """
    with client.session_transaction() as session:
        session['username'] = 'test_user_123'
    return client


# ============= DATA FIXTURES =============

@pytest.fixture
def sample_user():
    """
    Test için örnek kullanıcı verisi
    
    Kullanım:
        def test_user(sample_user):
            username = sample_user['username']
            assert len(username) >= 3
    """
    return {
        'username': 'test_user_123',
        'password': 'TestPassword123!'
    }


@pytest.fixture
def sample_user_hashed(sample_user):
    """
    Şifresi hashlenmiş test kullanıcısı
    
    Ne İşe Yarar:
        Veritabanında olduğu gibi hash'lenmiş şifre içerir.
        Password verification testleri için kullanılır.
    """
    user_data = sample_user.copy()
    user_data['hashed_password'] = hash_password(sample_user['password'])
    return user_data


@pytest.fixture
def sample_message():
    """
    Test için örnek mesaj verisi
    """
    return {
        'sender': 'alice',
        'receiver': 'bob',
        'content': 'Merhaba, bu bir test mesajıdır! 🔒',
        'timestamp': datetime.now()
    }


@pytest.fixture
def multiple_users():
    """
    Birden fazla test kullanıcısı (mesajlaşma testleri için)
    """
    return [
        {'username': 'alice', 'password': 'AlicePass123'},
        {'username': 'bob', 'password': 'BobPass456'},
        {'username': 'charlie', 'password': 'CharliePass789'}
    ]


# ============= GÜVENLİK TEST VERİLERİ =============

@pytest.fixture
def malicious_inputs():
    """
    Güvenlik testleri için zararlı input örnekleri
    
    XSS, SQL Injection, Path Traversal denemeleri.
    Bu inputlar validate fonksiyonları tarafından REJect edilmeli.
    """
    return {
        'xss_attempts': [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "<svg onload=alert(1)>",
            "<iframe src='javascript:alert(1)'></iframe>",
            "'-alert(1)-'",
            "<body onload=alert(1)>"
        ],
        'sql_injection_attempts': [
            "admin' OR '1'='1",
            "'; DROP TABLE users--",
            "admin'--",
            "1' UNION SELECT NULL--",
            "'; DELETE FROM messages--",
            "1; SELECT * FROM users",
            "' OR ''='"
        ],
        'path_traversal_attempts': [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32",
            "....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f"
        ]
    }


# ============= HELPER FUNCTIONS =============

def create_test_user(client, username='testuser', password='TestPass123'):
    """
    Test kullanıcısı oluşturma helper fonksiyonu
    """
    return client.post('/register', data={
        'username': username,
        'password': password
    }, follow_redirects=True)


def login_test_user(client, username='testuser', password='TestPass123'):
    """
    Test kullanıcısı ile giriş yapma helper fonksiyonu
    """
    return client.post('/login', data={
        'username': username,
        'password': password
    }, follow_redirects=True)


# ============= PYTEST HOOKS =============

def pytest_configure(config):
    """Pytest başlamadan önce çalışır"""
    print("\n" + "=" * 60)
    print("🧪 SECURE MESSAGE SYSTEM - TEST SUITE")
    print("=" * 60)


def pytest_sessionfinish(session, exitstatus):
    """Tüm testler bittikten sonra çalışır"""
    print("\n" + "=" * 60)
    if exitstatus == 0:
        print("✅ TÜM TESTLER BAŞARILI!")
    else:
        print("❌ BAZI TESTLER BAŞARISIZ!")
    print("=" * 60)

