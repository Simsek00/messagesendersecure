"""
Cryptography Test Suite
=======================

Bu dosya şifreleme fonksiyonlarını test eder:
1. Password Hashing (Bcrypt)
2. Message Encryption (Fernet/AES-256)

TEST EDİLEN FONKSİYONLAR:
- hash_password(): Şifreyi bcrypt ile hashler
- verify_password(): Hash'i doğrular
- encrypt_message(): Mesajı AES ile şifreler
- decrypt_message(): Şifreli mesajı çözer

ÇALIŞTIRMA:
    pytest tests/test_crypto.py -v
    pytest tests/test_crypto.py -k "password"  # Sadece password testleri
"""
import pytest
import sys
import os

# Ana dizini path'e ekle
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import hash_password, verify_password, encrypt_message, decrypt_message


# ============= BCRYPT PASSWORD HASHING TESTLERİ =============

class TestPasswordHashing:
    """
    Bcrypt şifre hashleme testleri
    
    BCRYPT NEDİR?
    - Güvenli password hashing algoritması
    - Her hash farklı salt içerir
    - Brute-force saldırılarına dayanıklı
    """
    
    def test_hash_password_returns_string(self):
        """
        TEST: hash_password() string döndürmeli
        
        AÇIKLAMA:
        Hash sonucu veritabanında saklanacak,
        bu yüzden string formatında olmalı.
        """
        password = "TestPassword123"
        hashed = hash_password(password)
        
        assert isinstance(hashed, str), "Hash string olmalı"
        assert len(hashed) > 0, "Hash boş olmamalı"
    
    def test_hash_password_different_each_time(self):
        """
        TEST: Aynı şifre farklı hash'ler üretmeli (SALT)
        
        AÇIKLAMA:
        Bcrypt her seferinde farklı salt kullanır.
        Bu sayede rainbow table saldırıları engellenir.
        """
        password = "SamePassword"
        hash1 = hash_password(password)
        hash2 = hash_password(password)
        
        # İki hash farklı olmalı (farklı salt)
        assert hash1 != hash2, "Aynı şifre farklı hash üretmeli (salt)"
    
    def test_hash_starts_with_bcrypt_prefix(self):
        """
        TEST: Bcrypt hash formatı doğru olmalı
        
        AÇIKLAMA:
        Bcrypt hash'leri '$2b$' ile başlar.
        Format: $2b$rounds$salt+hash
        """
        password = "test123"
        hashed = hash_password(password)
        
        assert hashed.startswith('$2b$'), "Bcrypt formatı $2b$ ile başlamalı"
    
    def test_verify_password_correct(self):
        """
        TEST: Doğru şifre verify edilmeli
        
        AÇIKLAMA:
        Kullanıcı doğru şifreyi girdiğinde True dönmeli.
        """
        password = "MySecretPass123"
        hashed = hash_password(password)
        
        result = verify_password(password, hashed)
        
        assert result is True, "Doğru şifre True dönmeli"
    
    def test_verify_password_incorrect(self):
        """
        TEST: Yanlış şifre reject edilmeli
        
        AÇIKLAMA:
        Hacker yanlış şifre denediğinde False dönmeli.
        """
        correct_password = "CorrectPassword"
        wrong_password = "WrongPassword"
        hashed = hash_password(correct_password)
        
        result = verify_password(wrong_password, hashed)
        
        assert result is False, "Yanlış şifre False dönmeli"
    
    def test_verify_password_case_sensitive(self):
        """
        TEST: Şifre büyük/küçük harf duyarlı olmalı
        
        AÇIKLAMA:
        "Password" ve "password" farklı şifreler.
        """
        password = "TestPassword"
        hashed = hash_password(password)
        
        # Küçük harfle deneme
        assert verify_password("testpassword", hashed) is False
        # Büyük harfle deneme
        assert verify_password("TESTPASSWORD", hashed) is False
        # Doğru şekilde
        assert verify_password("TestPassword", hashed) is True
    
    def test_hash_password_unicode_support(self):
        """
        TEST: Unicode karakterler desteklenmeli
        
        AÇIKLAMA:
        Türkçe karakterler, emoji vb. şifrede kullanılabilmeli.
        """
        password = "Şifre123Çok#Güçlü"
        hashed = hash_password(password)
        
        assert verify_password(password, hashed) is True
    
    def test_verify_empty_password(self):
        """
        TEST: Boş şifre güvenli şekilde handle edilmeli
        
        AÇIKLAMA:
        Boş şifre ile verify False dönmeli, crash olmamalı.
        """
        hashed = hash_password("something")
        
        result = verify_password("", hashed)
        
        assert result is False, "Boş şifre False dönmeli"
    
    def test_hash_password_minimum_length(self):
        """
        TEST: Minimum uzunlukta şifre hashlenebilmeli
        """
        short_password = "123456"  # 6 karakter minimum
        hashed = hash_password(short_password)
        
        assert verify_password(short_password, hashed) is True


# ============= FERNET MESSAGE ENCRYPTION TESTLERİ =============

class TestMessageEncryption:
    """
    Fernet (AES-256) mesaj şifreleme testleri
    
    FERNET NEDİR?
    - Symmetric encryption (aynı key ile şifrele/çöz)
    - AES-256-CBC + HMAC kullanır
    - Güvenli ve hızlı
    """
    
    def test_encrypt_message_returns_string(self):
        """
        TEST: encrypt_message() string döndürmeli
        
        AÇIKLAMA:
        Şifreli mesaj veritabanında saklanacak,
        bu yüzden string (base64) formatında olmalı.
        """
        message = "Test mesajı"
        encrypted = encrypt_message(message)
        
        assert isinstance(encrypted, str), "Encrypted string olmalı"
        assert len(encrypted) > 0, "Encrypted boş olmamalı"
    
    def test_encrypted_different_from_original(self):
        """
        TEST: Şifreli mesaj orijinalden farklı olmalı
        
        AÇIKLAMA:
        Şifreleme çalışıyorsa, çıktı girdiden farklı olmalı.
        """
        message = "Gizli mesaj"
        encrypted = encrypt_message(message)
        
        assert encrypted != message, "Şifreli mesaj orijinalden farklı olmalı"
    
    def test_decrypt_encrypted_message(self):
        """
        TEST: Şifrelenmiş mesaj doğru çözülmeli
        
        AÇIKLAMA:
        Encrypt -> Decrypt sonrası orijinal mesaj gelmeli.
        """
        original = "Gizli mesaj içeriği"
        encrypted = encrypt_message(original)
        decrypted = decrypt_message(encrypted)
        
        assert decrypted == original, "Decrypt sonrası orijinal mesaj gelmeli"
    
    def test_encrypt_empty_string(self):
        """
        TEST: Boş string şifrelenebilmeli
        
        AÇIKLAMA:
        Boş mesaj da geçerli bir mesajdır.
        """
        encrypted = encrypt_message("")
        decrypted = decrypt_message(encrypted)
        
        assert decrypted == "", "Boş string doğru şifrelenmeli"
    
    def test_encrypt_long_message(self):
        """
        TEST: Uzun mesaj şifrelenebilmeli (5000 karakter)
        
        AÇIKLAMA:
        Maksimum mesaj uzunluğu 5000 karakter.
        """
        long_message = "A" * 5000
        encrypted = encrypt_message(long_message)
        decrypted = decrypt_message(encrypted)
        
        assert decrypted == long_message, "Uzun mesaj doğru şifrelenmeli"
        assert len(decrypted) == 5000
    
    def test_encrypt_unicode_characters(self):
        """
        TEST: Unicode karakterler şifrelenebilmeli
        
        AÇIKLAMA:
        Türkçe, emoji, özel karakterler desteklenmeli.
        """
        message = "Türkçe özel karakterler: ğüşıöç 🔒🔑 مرحبا 中文"
        encrypted = encrypt_message(message)
        decrypted = decrypt_message(encrypted)
        
        assert decrypted == message, "Unicode karakterler korunmalı"
    
    def test_encrypt_special_characters(self):
        """
        TEST: Özel karakterler şifrelenebilmeli
        
        AÇIKLAMA:
        HTML, SQL vb. karakterler güvenle şifrelenmeli.
        """
        message = "<script>alert('test')</script> ' OR '1'='1"
        encrypted = encrypt_message(message)
        decrypted = decrypt_message(encrypted)
        
        assert decrypted == message, "Özel karakterler korunmalı"
    
    def test_decrypt_invalid_ciphertext(self):
        """
        TEST: Geçersiz ciphertext güvenli handle edilmeli
        
        AÇIKLAMA:
        Yanlış formatla decrypt denenmesi crash'e yol açmamalı.
        """
        invalid_encrypted = "invalid_base64_string_here"
        result = decrypt_message(invalid_encrypted)
        
        assert result == "[Şifre çözülemedi]", "Geçersiz input hata mesajı dönmeli"
    
    def test_decrypt_tampered_ciphertext(self):
        """
        TEST: Değiştirilmiş ciphertext reject edilmeli
        
        AÇIKLAMA:
        Birisi şifreli mesajı değiştirdiyse decrypt başarısız olmalı.
        (Integrity check - HMAC)
        """
        message = "Original message"
        encrypted = encrypt_message(message)
        
        # Ciphertext'i değiştir
        tampered = encrypted[:-5] + "XXXXX"
        result = decrypt_message(tampered)
        
        assert result == "[Şifre çözülemedi]", "Değiştirilmiş mesaj reject edilmeli"


# ============= ENTEGRASYON TESTLERİ =============

class TestCryptoIntegration:
    """
    Crypto modülü entegrasyon testleri
    
    Gerçek kullanım senaryolarını test eder.
    """
    
    def test_full_password_lifecycle(self):
        """
        TEST: Tam şifre yaşam döngüsü
        
        SENARYO:
        1. Kullanıcı kayıt olur -> şifre hashlenir
        2. Kullanıcı giriş yapar -> hash doğrulanır
        3. Yanlış şifre denenir -> reject edilir
        """
        raw_password = "UserPassword123"
        
        # 1. Registration - Hash
        hashed = hash_password(raw_password)
        stored_hash = hashed  # DB'ye kaydedildi
        
        # 2. Login - Verification (doğru şifre)
        assert verify_password(raw_password, stored_hash) is True
        
        # 3. Login attempt - Wrong password
        assert verify_password("WrongPass", stored_hash) is False
        assert verify_password("userpassword123", stored_hash) is False
    
    def test_full_message_encryption_lifecycle(self):
        """
        TEST: Tam mesaj şifreleme döngüsü
        
        SENARYO:
        1. Kullanıcı mesaj yazar
        2. Mesaj şifrelenir ve DB'ye kaydedilir
        3. Alıcı mesajı çeker ve decrypt eder
        """
        original_message = "Merhaba! Bu gizli bir mesajdır. 🔒"
        
        # 1. Encrypt (göndermeden önce)
        encrypted = encrypt_message(original_message)
        stored_encrypted = encrypted  # Firestore'a kaydedildi
        
        # 2. Şifreli mesajın okunamaması
        assert stored_encrypted != original_message
        
        # 3. Decrypt (alıcı tarafında)
        decrypted = decrypt_message(stored_encrypted)
        
        assert decrypted == original_message
    
    def test_multiple_messages_different_ciphertext(self):
        """
        TEST: Aynı mesaj farklı ciphertext üretebilir
        
        AÇIKLAMA:
        Fernet her encryption'da farklı IV kullanır.
        Bu güvenlik için önemlidir.
        """
        message = "Same message"
        
        encrypted1 = encrypt_message(message)
        encrypted2 = encrypt_message(message)
        
        # Her ikisi de aynı mesaja decrypt olmalı
        assert decrypt_message(encrypted1) == message
        assert decrypt_message(encrypted2) == message

