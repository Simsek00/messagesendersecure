"""
Test Package for Secure Message System
======================================

Bu paket, Secure Message System için kapsamlı test süitini içerir.

Test Kategorileri:
- test_crypto.py: Şifreleme/çözme testleri (Bcrypt + Fernet)
- test_validation.py: Input validation testleri (XSS/Injection koruması)
- test_auth.py: Authentication testleri (Login/Register)
- test_routes.py: Flask route testleri
- test_security.py: Güvenlik testleri

Kullanım:
    pytest                      # Tüm testleri çalıştır
    pytest -v                   # Detaylı output
    pytest tests/test_crypto.py # Sadece crypto testleri
    pytest -k "password"        # "password" içeren testler
"""

__version__ = "1.0.0"
__author__ = "Secure Message Team"
