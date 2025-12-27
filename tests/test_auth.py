"""
Authentication Test Suite
==========================

Bu dosya kullanıcı kimlik doğrulama sistemini test eder.

TEST EDİLEN İŞLEVLER:
- Kullanıcı kaydı (Register)
- Kullanıcı girişi (Login)
- Oturum yönetimi (Session)
- Çıkış yapma (Logout)

ÇALIŞTIRMA:
    pytest tests/test_auth.py -v
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import hash_password, verify_password


# ============= AUTHENTICATION UNIT TESTLERİ =============

class TestAuthenticationLogic:
    """
    Authentication mantık testleri
    
    Bu testler veritabanı kullanmadan authentication
    fonksiyonlarının doğru çalışıp çalışmadığını kontrol eder.
    """
    
    def test_password_hash_and_verify_flow(self):
        """
        TEST: Kayıt -> Giriş akışı
        
        SENARYO:
        1. Kullanıcı kayıt olur (şifre hashlenir)
        2. Kullanıcı giriş yapar (hash doğrulanır)
        """
        # Kayıt: Şifre hashlenir
        raw_password = "UserPassword123"
        hashed = hash_password(raw_password)
        
        # Simüle: Hash veritabanına kaydedildi
        db_stored_hash = hashed
        
        # Giriş: Kullanıcı aynı şifreyi girer
        login_attempt = "UserPassword123"
        is_valid = verify_password(login_attempt, db_stored_hash)
        
        assert is_valid is True, "Doğru şifre ile giriş yapılabilmeli"
    
    def test_wrong_password_rejected(self):
        """
        TEST: Yanlış şifre ile giriş engellenmeli
        
        SENARYO:
        Hacker yanlış şifre dener -> REJECT
        """
        correct_password = "CorrectPass123"
        hashed = hash_password(correct_password)
        
        # Hacker denemesi
        hack_attempts = [
            "wrongpassword",
            "CorrectPass",
            "correctpass123",
            "CORRECTPASS123",
            "",
            " CorrectPass123",
            "CorrectPass123 "
        ]
        
        for attempt in hack_attempts:
            is_valid = verify_password(attempt, hashed)
            assert is_valid is False, f"'{attempt}' reject edilmeli"
    
    def test_different_users_different_hashes(self):
        """
        TEST: Aynı şifre kullanan farklı kullanıcılar farklı hash'lere sahip olmalı
        
        AÇIKLAMA:
        Bu sayede bir kullanıcının hash'i sızsa bile
        aynı şifreyi kullanan diğer kullanıcılar korunur.
        """
        password = "CommonPassword123"
        
        user1_hash = hash_password(password)
        user2_hash = hash_password(password)
        
        # Her iki kullanıcı da giriş yapabilmeli
        assert verify_password(password, user1_hash) is True
        assert verify_password(password, user2_hash) is True
        
        # Ama hash'ler farklı olmalı
        assert user1_hash != user2_hash, "Farklı salt = farklı hash"


# ============= SESSION TESTLERİ =============

class TestSessionManagement:
    """
    Oturum yönetimi testleri
    
    Flask session kullanarak login durumunu test eder.
    """
    
    def test_session_stores_username(self, client):
        """
        TEST: Session'a username kaydedilebilmeli
        """
        with client.session_transaction() as session:
            session['username'] = 'test_user'
        
        with client.session_transaction() as session:
            assert 'username' in session
            assert session['username'] == 'test_user'
    
    def test_session_cleared_on_logout(self, authenticated_client):
        """
        TEST: Logout sonrası session temizlenmeli
        """
        # Önce session'da kullanıcı var
        with authenticated_client.session_transaction() as session:
            assert 'username' in session
        
        # Logout
        authenticated_client.get('/logout', follow_redirects=True)
        
        # Session temizlendi mi?
        with authenticated_client.session_transaction() as session:
            assert 'username' not in session


# ============= ROUTE TESTLERİ =============

class TestAuthRoutes:
    """
    Authentication route testleri
    
    HTTP endpoint'lerini test eder.
    """
    
    def test_login_page_loads(self, client):
        """TEST: Login sayfası yüklenmeli"""
        response = client.get('/')
        
        assert response.status_code == 200
    
    def test_register_page_loads(self, client):
        """TEST: Register sayfası yüklenmeli"""
        response = client.get('/register')
        
        assert response.status_code == 200
    
    def test_dashboard_requires_login(self, client):
        """
        TEST: Dashboard login gerektirmeli
        
        Login olmadan dashboard'a gitmeye çalışınca
        login sayfasına yönlendirilmeli.
        """
        response = client.get('/dashboard')
        
        # 302 = Redirect (login'e)
        assert response.status_code == 302, "Login olmadan redirect olmalı"
    
    def test_dashboard_accessible_when_logged_in(self, authenticated_client):
        """
        TEST: Login sonrası dashboard erişilebilir olmalı
        """
        response = authenticated_client.get('/dashboard')
        
        # Not: Firebase mock olmadığı için 500 olabilir
        # Ama 302 (redirect) olmamalı
        assert response.status_code != 302, "Login ile redirect olmamalı"
    
    def test_logout_redirects_to_login(self, authenticated_client):
        """
        TEST: Logout sonrası login'e yönlendirmeli
        """
        response = authenticated_client.get('/logout', follow_redirects=False)
        
        assert response.status_code == 302, "Logout redirect vermeli"
    
    def test_profile_requires_login(self, client):
        """
        TEST: Profile sayfası login gerektirmeli
        """
        response = client.get('/profile')
        
        assert response.status_code == 302, "Login olmadan profile redirect olmalı"


# ============= BRUTE FORCE KORUMA TESTLERİ =============

class TestBruteForceProtection:
    """
    Brute force saldırı koruması testleri
    
    NOT: Rate limiting implement edilmemişse bu testler SKIP edilir.
    """
    
    @pytest.mark.skip(reason="Rate limiting henüz implement edilmedi")
    def test_multiple_failed_logins_blocked(self, client):
        """
        TEST: Çok fazla başarısız giriş engellemeli
        
        SENARYO:
        5+ başarısız denemeden sonra hesap/IP engellenmeli.
        """
        for i in range(10):
            client.post('/login', data={
                'username': 'test',
                'password': f'wrong_password_{i}'
            })
        
        # 6. denemede engellemeli
        response = client.post('/login', data={
            'username': 'test',
            'password': 'another_wrong'
        })
        
        assert b'too many attempts' in response.data.lower()

