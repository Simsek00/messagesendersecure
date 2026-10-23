"""
Input Validation Test Suite
============================

Bu dosya kullanıcı girişlerinin doğrulamasını test eder.

TEST EDİLEN FONKSİYONLAR:
- validate_username(): Kullanıcı adı doğrulama
- validate_password(): Şifre doğrulama
- validate_message(): Mesaj içeriği doğrulama

GÜVENLİK AMACI:
- XSS (Cross-Site Scripting) önleme
- SQL/NoSQL Injection önleme
- Zararlı input filtreleme

ÇALIŞTIRMA:
    pytest tests/test_validation.py -v
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import validate_username, validate_password, validate_message, hash_password, verify_password


# ============= USERNAME VALIDATION TESTLERİ =============

class TestUsernameValidation:
    """
    Kullanıcı adı doğrulama testleri
    
    KURALLAR:
    - Minimum 3, maksimum 20 karakter
    - Sadece: harf (a-z, A-Z), rakam (0-9), alt çizgi (_)
    - Boşluk ve özel karakterler YASAK
    """
    
    def test_valid_username_simple(self):
        """TEST: Basit geçerli kullanıcı adı"""
        valid, result = validate_username("testuser")
        
        assert valid is True, "Basit username kabul edilmeli"
        assert result == "testuser"
    
    def test_valid_username_with_numbers(self):
        """TEST: Rakam içeren kullanıcı adı"""
        valid, result = validate_username("user123")
        
        assert valid is True, "Rakamlı username kabul edilmeli"
    
    def test_valid_username_with_underscore(self):
        """TEST: Alt çizgi içeren kullanıcı adı"""
        valid, result = validate_username("test_user_123")
        
        assert valid is True, "Alt çizgili username kabul edilmeli"
    
    def test_valid_username_minimum_length(self):
        """TEST: Minimum uzunluk (3 karakter)"""
        valid, result = validate_username("abc")
        
        assert valid is True, "3 karakterlik username kabul edilmeli"
    
    def test_valid_username_maximum_length(self):
        """TEST: Maksimum uzunluk (20 karakter)"""
        valid, result = validate_username("a" * 20)
        
        assert valid is True, "20 karakterlik username kabul edilmeli"
    
    def test_invalid_username_too_short(self):
        """TEST: Çok kısa kullanıcı adı (2 karakter)"""
        valid, msg = validate_username("ab")
        
        assert valid is False, "2 karakter reject edilmeli"
        assert "en az 3" in msg.lower()
    
    def test_invalid_username_too_long(self):
        """TEST: Çok uzun kullanıcı adı (21 karakter)"""
        valid, msg = validate_username("a" * 21)
        
        assert valid is False, "21 karakter reject edilmeli"
        assert "en fazla 20" in msg.lower()
    
    def test_invalid_username_empty(self):
        """TEST: Boş kullanıcı adı"""
        valid, msg = validate_username("")
        
        assert valid is False, "Boş username reject edilmeli"
        assert "boş" in msg.lower()
    
    def test_invalid_username_with_space(self):
        """TEST: Boşluk içeren kullanıcı adı"""
        valid, msg = validate_username("test user")
        
        assert valid is False, "Boşluklu username reject edilmeli"
    
    def test_invalid_username_with_special_chars(self):
        """TEST: Özel karakter içeren kullanıcı adları"""
        special_usernames = [
            "user@name",    # @ işareti
            "user-name",    # tire
            "user.name",    # nokta
            "user!name",    # ünlem
            "user#name",    # hashtag
            "user$name",    # dolar
        ]
        for username in special_usernames:
            valid, msg = validate_username(username)
            assert valid is False, f"'{username}' reject edilmeli"
    
    def test_username_trim_whitespace(self):
        """TEST: Baş/sondaki boşluklar temizlenmeli"""
        valid, result = validate_username("  testuser  ")
        
        assert valid is True, "Trimmed username kabul edilmeli"
        assert result == "testuser", "Boşluklar temizlenmeli"
    
    # ===== XSS PREVENTION TESTS =====
    
    def test_xss_script_tag_blocked(self):
        """TEST: <script> tag XSS engellenmeli"""
        valid, msg = validate_username("<script>alert('xss')</script>")
        
        assert valid is False, "XSS script tag reject edilmeli"
    
    def test_xss_img_onerror_blocked(self):
        """TEST: img onerror XSS engellenmeli"""
        valid, msg = validate_username("<img src=x onerror=alert(1)>")
        
        assert valid is False, "XSS img tag reject edilmeli"
    
    def test_xss_javascript_protocol_blocked(self):
        """TEST: javascript: protocol engellenmeli"""
        valid, msg = validate_username("javascript:alert(1)")
        
        assert valid is False, "javascript: protocol reject edilmeli"
    
    # ===== SQL INJECTION PREVENTION TESTS =====
    
    def test_sql_injection_or_blocked(self):
        """TEST: SQL OR injection engellenmeli"""
        valid, msg = validate_username("admin' OR '1'='1")
        
        assert valid is False, "SQL injection reject edilmeli"
    
    def test_sql_injection_drop_blocked(self):
        """TEST: SQL DROP injection engellenmeli"""
        valid, msg = validate_username("'; DROP TABLE users--")
        
        assert valid is False, "SQL DROP injection reject edilmeli"
    
    def test_sql_injection_comment_blocked(self):
        """TEST: SQL comment injection engellenmeli"""
        valid, msg = validate_username("admin'--")
        
        assert valid is False, "SQL comment injection reject edilmeli"


# ============= PASSWORD VALIDATION TESTLERİ =============

class TestPasswordValidation:
    """
    Şifre doğrulama testleri
    
    KURALLAR:
    - Minimum 6 karakter, maksimum 72 byte (bcrypt sınırı)
    - Özel karakterler KABUL EDİLİR (güçlü şifre için)
    """
    
    def test_valid_password_simple(self):
        """TEST: Basit geçerli şifre"""
        valid, msg = validate_password("password123")
        
        assert valid is True, "Basit şifre kabul edilmeli"
    
    def test_valid_password_minimum_length(self):
        """TEST: Minimum uzunluk (6 karakter)"""
        valid, msg = validate_password("123456")
        
        assert valid is True, "6 karakterlik şifre kabul edilmeli"
    
    def test_valid_password_with_special_chars(self):
        """TEST: Özel karakterli güçlü şifre"""
        valid, msg = validate_password("P@ssw0rd!#$%")
        
        assert valid is True, "Özel karakterli şifre kabul edilmeli"
    
    def test_valid_password_unicode(self):
        """TEST: Unicode karakterli şifre"""
        valid, msg = validate_password("Şifre123Güçlü")
        
        assert valid is True, "Unicode şifre kabul edilmeli"
    
    def test_valid_password_with_emoji(self):
        """TEST: Emoji içeren şifre"""
        valid, msg = validate_password("Pass🔒word123")
        
        assert valid is True, "Emoji şifre kabul edilmeli"
    
    def test_invalid_password_too_short(self):
        """TEST: Çok kısa şifre (5 karakter)"""
        valid, msg = validate_password("12345")
        
        assert valid is False, "5 karakter reject edilmeli"
        assert "en az 6" in msg.lower()
    
    def test_invalid_password_empty(self):
        """TEST: Boş şifre"""
        valid, msg = validate_password("")
        
        assert valid is False, "Boş şifre reject edilmeli"
        assert "boş" in msg.lower()
    
    def test_invalid_password_too_long(self):
        """TEST: Çok uzun şifre (73 byte)"""
        valid, msg = validate_password("a" * 73)
        
        assert valid is False, "73 byte reject edilmeli"
        assert "uzun" in msg.lower()
    
    def test_valid_password_maximum_length(self):
        """TEST: Maksimum uzunluk (72 byte)"""
        valid, msg = validate_password("a" * 72)
        
        assert valid is True, "72 byte'lık şifre kabul edilmeli"
    
    def test_invalid_password_multibyte_over_limit(self):
        """TEST: 37 Türkçe karakter = 74 byte, bcrypt sınırını aşar"""
        valid, msg = validate_password("ş" * 37)
        
        assert valid is False, "72 byte'ı aşan Türkçe şifre reject edilmeli"
    
    def test_max_length_password_can_be_hashed(self):
        """TEST: Kabul edilen en uzun şifre bcrypt ile hashlenebilmeli"""
        password = "ş" * 36  # 72 byte
        valid, _ = validate_password(password)
        
        assert valid is True
        assert verify_password(password, hash_password(password)) is True


# ============= MESSAGE VALIDATION TESTLERİ =============

class TestMessageValidation:
    """
    Mesaj içeriği doğrulama testleri
    
    KURALLAR:
    - Boş olamaz
    - Maksimum 5000 karakter
    - Tüm karakterler KABUL EDİLİR (şifrelenecek)
    """
    
    def test_valid_message_simple(self):
        """TEST: Basit geçerli mesaj"""
        valid, result = validate_message("Merhaba, nasılsın?")
        
        assert valid is True, "Basit mesaj kabul edilmeli"
        assert result == "Merhaba, nasılsın?"
    
    def test_valid_message_unicode(self):
        """TEST: Unicode karakterli mesaj"""
        valid, result = validate_message("Türkçe mesaj ğüşıöç")
        
        assert valid is True, "Unicode mesaj kabul edilmeli"
    
    def test_valid_message_with_emoji(self):
        """TEST: Emoji içeren mesaj"""
        valid, result = validate_message("Harika! 🎉🔒👍")
        
        assert valid is True, "Emoji mesaj kabul edilmeli"
    
    def test_valid_message_maximum_length(self):
        """TEST: Maksimum uzunluk (5000 karakter)"""
        valid, result = validate_message("A" * 5000)
        
        assert valid is True, "5000 karakter kabul edilmeli"
        assert len(result) == 5000
    
    def test_invalid_message_empty(self):
        """TEST: Boş mesaj"""
        valid, msg = validate_message("")
        
        assert valid is False, "Boş mesaj reject edilmeli"
        assert "boş" in msg.lower()
    
    def test_invalid_message_whitespace_only(self):
        """TEST: Sadece boşluk içeren mesaj"""
        valid, msg = validate_message("     ")
        
        assert valid is False, "Sadece boşluk reject edilmeli"
    
    def test_invalid_message_too_long(self):
        """TEST: Çok uzun mesaj (5001 karakter)"""
        valid, msg = validate_message("A" * 5001)
        
        assert valid is False, "5001 karakter reject edilmeli"
        assert "uzun" in msg.lower()
    
    def test_message_trim_whitespace(self):
        """TEST: Baş/sondaki boşluklar temizlenmeli"""
        valid, result = validate_message("  Test mesajı  ")
        
        assert valid is True
        assert result == "Test mesajı", "Boşluklar temizlenmeli"
    
    def test_message_allows_html_tags(self):
        """
        TEST: HTML tagleri mesajda kabul edilir
        
        AÇIKLAMA:
        Mesaj içeriği şifrelenecek, XSS frontend'de escape edilecek.
        Bu yüzden validation HTML'e izin verir.
        """
        valid, result = validate_message("<b>Kalın</b> <i>italik</i>")
        
        assert valid is True, "HTML mesajda kabul edilmeli (şifrelenecek)"
    
    def test_message_allows_special_chars(self):
        """TEST: Özel karakterler mesajda kabul edilir"""
        valid, result = validate_message("!@#$%^&*(){}[]|\\:\";<>?,./")
        
        assert valid is True, "Özel karakterler kabul edilmeli"

