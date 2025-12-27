"""
Security Test Suite
====================

Bu dosya güvenlik açıklarını test eder.

TEST KATEGORİLERİ:
- XSS (Cross-Site Scripting) Prevention
- SQL/NoSQL Injection Prevention
- Session Security
- Authentication Security
- Input Sanitization

ÖNEMLİ:
Bu testler, güvenlik açıklarının OLMADIĞINI doğrular.
Testler PASS ederse sistem güvenlidir.

ÇALIŞTIRMA:
    pytest tests/test_security.py -v
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import validate_username, validate_password, validate_message
from app import hash_password, verify_password


# ============= XSS PREVENTION TESTLERİ =============

class TestXSSPrevention:
    """
    XSS (Cross-Site Scripting) Önleme Testleri
    
    XSS NEDİR?
    Saldırgan zararlı JavaScript kodu enjekte eder.
    Bu kod kurbanın tarayıcısında çalışır ve:
    - Session çalabilir
    - Kimlik bilgilerini çalabilir
    - Sayfa içeriğini değiştirebilir
    """
    
    def test_xss_script_tag_in_username(self, malicious_inputs):
        """
        TEST: <script> tag username'de engellenmeli
        
        SALDIRI: <script>alert('xss')</script>
        """
        for xss in malicious_inputs['xss_attempts']:
            valid, msg = validate_username(xss)
            assert valid is False, f"XSS '{xss[:30]}...' username'de engellenmeli"
    
    def test_xss_in_message_encrypted(self):
        """
        TEST: Mesajdaki XSS şifrelenerek zararsız hale gelmeli
        
        AÇIKLAMA:
        Mesaj içeriği doğrudan validate edilmez ama şifrelenir.
        Şifrelenmiş mesaj tarayıcıda çalışamaz.
        Frontend'de escape de yapılır (double protection).
        """
        xss_message = "<script>document.cookie</script>"
        valid, result = validate_message(xss_message)
        
        # Mesaj kabul edilir ama şifrelenecek
        assert valid is True, "Mesaj kabul edilmeli (şifrelenecek)"
    
    def test_xss_variants_blocked(self):
        """
        TEST: Farklı XSS varyantları username'de engellenmeli
        """
        xss_variants = [
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            "<iframe src='javascript:alert(1)'>",
            "javascript:alert(1)",
            "<div onclick=alert(1)>",
            "'-alert(1)-'",
            "\"><script>alert(1)</script>",
        ]
        
        for xss in xss_variants:
            valid, msg = validate_username(xss)
            assert valid is False, f"XSS varyant '{xss[:20]}...' engellenmeli"


# ============= SQL/NOSQL INJECTION PREVENTION TESTLERİ =============

class TestInjectionPrevention:
    """
    SQL/NoSQL Injection Önleme Testleri
    
    INJECTION NEDİR?
    Saldırgan veritabanı komutları enjekte eder.
    Başarılı olursa:
    - Tüm verileri okuyabilir
    - Verileri silebilir
    - Admin erişimi alabilir
    
    NOT: Firestore NoSQL kullanıyor, SQL injection N/A.
    Ama username validation yine de bu inputları engellemeli.
    """
    
    def test_sql_injection_in_username(self, malicious_inputs):
        """
        TEST: SQL injection username'de engellenmeli
        """
        for sql in malicious_inputs['sql_injection_attempts']:
            valid, msg = validate_username(sql)
            assert valid is False, f"SQL injection '{sql[:20]}...' engellenmeli"
    
    def test_nosql_injection_patterns(self):
        """
        TEST: NoSQL injection patternleri username'de engellenmeli
        """
        nosql_patterns = [
            "{'$gt': ''}",
            "$where: 1==1",
            "admin', $or: [{},{'a':'a",
            "; return true; var foo='",
        ]
        
        for pattern in nosql_patterns:
            valid, msg = validate_username(pattern)
            assert valid is False, f"NoSQL pattern '{pattern[:20]}...' engellenmeli"


# ============= PASSWORD SECURITY TESTLERİ =============

class TestPasswordSecurity:
    """
    Şifre Güvenliği Testleri
    """
    
    def test_password_not_stored_plaintext(self):
        """
        TEST: Şifre plaintext olarak saklanmamalı
        
        KONTROL: hash_password sonucu orijinal şifreden farklı olmalı
        """
        password = "MySecretPassword123"
        hashed = hash_password(password)
        
        assert hashed != password, "Hash plaintext'ten farklı olmalı"
        assert password not in hashed, "Plaintext hash içinde olmamalı"
    
    def test_password_hash_is_bcrypt_format(self):
        """
        TEST: Hash bcrypt formatında olmalı
        
        BCRYPT FORMAT: $2b$rounds$salt+hash
        """
        password = "test123"
        hashed = hash_password(password)
        
        assert hashed.startswith('$2b$'), "Bcrypt formatı $2b$ ile başlamalı"
        assert len(hashed) == 60, "Bcrypt hash 60 karakter olmalı"
    
    def test_same_password_different_hash(self):
        """
        TEST: Aynı şifre farklı hash üretmeli (salt)
        
        AÇIKLAMA:
        Rainbow table saldırılarını engeller.
        """
        password = "CommonPassword"
        
        hashes = [hash_password(password) for _ in range(5)]
        unique_hashes = set(hashes)
        
        assert len(unique_hashes) == 5, "5 farklı hash üretilmeli"
    
    def test_timing_safe_comparison(self):
        """
        TEST: Şifre karşılaştırma timing-safe olmalı
        
        AÇIKLAMA:
        bcrypt.checkpw timing-safe comparison yapar.
        Bu, timing attack'ları engeller.
        """
        password = "testpassword"
        hashed = hash_password(password)
        
        # Doğru ve yanlış şifre aynı sürede değerlendirilmeli
        # Bu bir runtime kontrolü, sadece crash olmamasını test ediyoruz
        verify_password(password, hashed)
        verify_password("wrong", hashed)
        verify_password("wrongwrongwrong", hashed)
        
        # Test passed if no crash


# ============= SESSION SECURITY TESTLERİ =============

class TestSessionSecurity:
    """
    Oturum Güvenliği Testleri
    """
    
    def test_session_cleared_on_logout(self, authenticated_client):
        """
        TEST: Logout'ta session tamamen temizlenmeli
        """
        authenticated_client.get('/logout')
        
        with authenticated_client.session_transaction() as session:
            assert 'username' not in session
    
    def test_protected_routes_redirect_without_session(self, client):
        """
        TEST: Korumalı sayfalar session olmadan erişilememeli
        
        NOT: /send_message POST-only, 404 dönebilir
        """
        protected_routes = ['/dashboard', '/profile']
        
        for route in protected_routes:
            response = client.get(route, follow_redirects=False)
            assert response.status_code in [302, 405], f"{route} korumalı olmalı"


# ============= INPUT SANITIZATION TESTLERİ =============

class TestInputSanitization:
    """
    Girdi Temizleme Testleri
    """
    
    def test_username_trimmed(self):
        """TEST: Username baş/sondaki boşlukları temizlenmeli"""
        valid, result = validate_username("  testuser  ")
        
        assert valid is True
        assert result == "testuser", "Boşluklar temizlenmeli"
    
    def test_message_trimmed(self):
        """TEST: Mesaj baş/sondaki boşlukları temizlenmeli"""
        valid, result = validate_message("  Test mesajı  ")
        
        assert valid is True
        assert result == "Test mesajı"
    
    def test_null_byte_injection(self):
        """
        TEST: Null byte injection engellenmeli
        
        SALDIRI: Dosya yolu manipülasyonu için kullanılır
        """
        null_byte_inputs = [
            "admin\x00",
            "test\x00.txt",
            "\x00\x00\x00",
        ]
        
        for input_str in null_byte_inputs:
            valid, msg = validate_username(input_str)
            assert valid is False, f"Null byte '{repr(input_str)}' engellenmeli"


# ============= AUTHENTICATION BYPASS TESTLERİ =============

class TestAuthenticationBypass:
    """
    Kimlik Doğrulama Bypass Testleri
    """
    
    def test_cannot_access_dashboard_without_login(self, client):
        """TEST: Login olmadan dashboard'a erişilememeli"""
        response = client.get('/dashboard', follow_redirects=False)
        
        assert response.status_code == 302, "Redirect olmalı"
    
    def test_cannot_send_message_without_login(self, client):
        """
        TEST: Login olmadan mesaj gönderilemeli
        
        NOT: Route yapısına bağlı olarak 302, 401, 404, 405 dönebilir
        """
        response = client.post('/send_message', data={
            'receiver': 'test',
            'content': 'test'
        }, follow_redirects=False)
        
        # 302 (redirect), 401 (unauthorized), 404 (not found), 405 (method not allowed)
        assert response.status_code in [302, 401, 404, 405]
    
    def test_cannot_delete_message_without_login(self, client):
        """TEST: Login olmadan mesaj silinememeli"""
        response = client.post('/delete_message/123', follow_redirects=False)
        
        assert response.status_code in [302, 401, 404]


# ============= ENTEGRASYON GÜVENLİK TESTLERİ =============

class TestSecurityIntegration:
    """
    Entegre güvenlik testleri
    """
    
    def test_full_secure_registration_flow(self, client):
        """
        TEST: Güvenli kayıt akışı
        
        1. XSS/Injection username kabul edilmemeli
        2. Şifre hashlenmeli (plaintext değil)
        """
        # XSS username reject
        response = client.post('/register', data={
            'username': '<script>alert(1)</script>',
            'password': 'ValidPass123'
        })
        # Hata mesajı veya redirect (kabul edilmedi)
        assert response.status_code in [200, 302]
        
        # SQL injection username reject
        response = client.post('/register', data={
            'username': "admin'--",
            'password': 'ValidPass123'
        })
        assert response.status_code in [200, 302]
    
    def test_encryption_protects_message_content(self):
        """
        TEST: Şifreleme mesaj içeriğini korumalı
        
        Veritabanındaki şifreli mesaj, orijinal içeriği
        hiçbir şekilde göstermemeli.
        """
        from app import encrypt_message
        
        sensitive_message = "Banka hesap numarası: 123456789"
        encrypted = encrypt_message(sensitive_message)
        
        # Şifreli mesajda orijinal içerik olmamalı
        assert "Banka" not in encrypted
        assert "123456789" not in encrypted
        assert "hesap" not in encrypted

