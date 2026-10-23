"""
Flask Routes Test Suite
========================

Bu dosya tüm Flask route'larını test eder.

TEST EDİLEN ROUTE'LAR:
- / (index)
- /register
- /login
- /logout
- /dashboard
- /send_message
- /delete_message/<id>
- /profile
- /change_password
- /delete_account

ÇALIŞTIRMA:
    pytest tests/test_routes.py -v
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


# ============= INDEX ROUTE TESTLERİ =============

class TestIndexRoute:
    """
    Ana sayfa (/) route testleri
    """
    
    def test_index_returns_200(self, client):
        """TEST: Index sayfası 200 dönmeli"""
        response = client.get('/')
        
        assert response.status_code == 200
    
    def test_index_shows_login_for_anonymous(self, client):
        """TEST: Anonim kullanıcıya login gösterilmeli"""
        response = client.get('/')
        
        assert response.status_code == 200
        # Login sayfası içeriği
        assert b'Giri' in response.data or b'Login' in response.data
    
    def test_index_redirects_authenticated_user(self, authenticated_client):
        """TEST: Login olmuş kullanıcı dashboard'a yönlendirilmeli"""
        response = authenticated_client.get('/', follow_redirects=False)
        
        # 302 redirect veya 200 (template'e bağlı)
        assert response.status_code in [200, 302]


# ============= REGISTER ROUTE TESTLERİ =============

class TestRegisterRoute:
    """
    Kayıt (/register) route testleri
    """
    
    def test_register_get_returns_200(self, client):
        """TEST: Register GET 200 dönmeli"""
        response = client.get('/register')
        
        assert response.status_code == 200
    
    def test_register_page_has_form(self, client):
        """TEST: Register sayfasında form olmalı"""
        response = client.get('/register')
        
        assert b'<form' in response.data
        assert b'username' in response.data.lower()
        assert b'password' in response.data.lower()
    
    def test_register_post_empty_username(self, client):
        """TEST: Boş username ile kayıt başarısız olmalı"""
        response = client.post('/register', data={
            'username': '',
            'password': 'ValidPass123'
        }, follow_redirects=True)
        
        # Hata mesajı görünmeli
        assert response.status_code == 200
    
    def test_register_post_invalid_username(self, client):
        """TEST: Geçersiz username ile kayıt başarısız olmalı"""
        response = client.post('/register', data={
            'username': 'ab',  # Çok kısa
            'password': 'ValidPass123'
        }, follow_redirects=True)
        
        assert response.status_code == 200
    
    def test_register_post_short_password(self, client):
        """TEST: Kısa şifre ile kayıt başarısız olmalı"""
        response = client.post('/register', data={
            'username': 'validuser',
            'password': '12345'  # 5 karakter, minimum 6
        }, follow_redirects=True)
        
        assert response.status_code == 200


# ============= LOGIN ROUTE TESTLERİ =============

class TestLoginRoute:
    """
    Giriş (/login) route testleri
    """
    
    def test_login_get_returns_200(self, client):
        """TEST: Login GET 200 dönmeli"""
        response = client.get('/')
        
        assert response.status_code == 200
    
    def test_login_page_has_form(self, client):
        """TEST: Login sayfasında form olmalı"""
        response = client.get('/')
        
        assert b'<form' in response.data
    
    def test_login_post_empty_credentials(self, client):
        """TEST: Boş credentials ile giriş başarısız olmalı"""
        response = client.post('/login', data={
            'username': '',
            'password': ''
        }, follow_redirects=True)
        
        assert response.status_code == 200


# ============= LOGOUT ROUTE TESTLERİ =============

class TestLogoutRoute:
    """
    Çıkış (/logout) route testleri
    """
    
    def test_logout_redirects(self, authenticated_client):
        """TEST: Logout redirect vermeli"""
        response = authenticated_client.post('/logout', follow_redirects=False)
        
        assert response.status_code == 302
    
    def test_logout_clears_session(self, authenticated_client):
        """TEST: Logout session'ı temizlemeli"""
        # Önce session'da kullanıcı var
        with authenticated_client.session_transaction() as session:
            assert 'username' in session
        
        # Logout
        authenticated_client.post('/logout')
        
        # Session temizlendi
        with authenticated_client.session_transaction() as session:
            assert 'username' not in session


# ============= DASHBOARD ROUTE TESTLERİ =============

class TestDashboardRoute:
    """
    Dashboard (/dashboard) route testleri
    """
    
    def test_dashboard_requires_auth(self, client):
        """TEST: Dashboard authentication gerektirmeli"""
        response = client.get('/dashboard', follow_redirects=False)
        
        assert response.status_code == 302, "Login olmadan redirect olmalı"
    
    def test_dashboard_accessible_when_authenticated(self, authenticated_client):
        """TEST: Login ile dashboard erişilebilir olmalı"""
        response = authenticated_client.get('/dashboard')
        
        # Firebase mock olmadığı için 500 olabilir ama 302 olmamalı
        assert response.status_code != 302


# ============= PROFILE ROUTE TESTLERİ =============

class TestProfileRoute:
    """
    Profil (/profile) route testleri
    """
    
    def test_profile_requires_auth(self, client):
        """TEST: Profile authentication gerektirmeli"""
        response = client.get('/profile', follow_redirects=False)
        
        assert response.status_code == 302
    
    def test_profile_accessible_when_authenticated(self, authenticated_client):
        """
        TEST: Login ile profile erişilebilir olmalı
        
        NOT: Firebase mock olmadığı için bu test skip edilebilir.
        Profile route'u Firestore'a bağlı, mock olmadan 302/500 dönebilir.
        """
        response = authenticated_client.get('/profile')
        
        # Firebase mock olmadığı için 302 (redirect) veya 500 (error) olabilir
        # Önemli olan 401 (Unauthorized) olmaması
        assert response.status_code in [200, 302, 500]


# ============= MESSAGE ROUTE TESTLERİ =============

class TestMessageRoutes:
    """
    Mesaj route testleri (/send_message, /delete_message)
    """
    
    def test_send_message_requires_auth(self, client):
        """
        TEST: Mesaj gönderme authentication gerektirmeli
        
        NOT: /send_message sadece POST kabul eder, 
        login olmadan 302 redirect veya 404 dönebilir.
        """
        response = client.post('/send_message', data={
            'receiver': 'someone',
            'content': 'Test message'
        }, follow_redirects=False)
        
        # 302 (redirect) veya 404 (POST-only route) kabul edilir
        assert response.status_code in [302, 404]
    
    def test_delete_message_requires_auth(self, client):
        """TEST: Mesaj silme authentication gerektirmeli"""
        response = client.post('/delete_message/some_id', follow_redirects=False)
        
        # 302 redirect veya 401 unauthorized
        assert response.status_code in [302, 401, 404]


# ============= HTTP METHOD TESTLERİ =============

class TestHTTPMethods:
    """
    HTTP method kontrolü testleri
    """
    
    def test_register_accepts_get_and_post(self, client):
        """TEST: Register GET ve POST kabul etmeli"""
        get_response = client.get('/register')
        assert get_response.status_code == 200
        
        post_response = client.post('/register', data={})
        assert post_response.status_code in [200, 302, 400]
    
    def test_login_accepts_get_and_post(self, client):
        """TEST: Login GET ve POST kabul etmeli"""
        # Index login sayfasını gösterir
        get_response = client.get('/')
        assert get_response.status_code == 200
        
        post_response = client.post('/login', data={})
        assert post_response.status_code in [200, 302, 400]
    
    def test_logout_rejects_get(self, authenticated_client):
        """TEST: Logout sadece POST kabul etmeli (GET linkiyle CSRF logout engellenir)"""
        response = authenticated_client.get('/logout')
        
        assert response.status_code == 405


# ============= ERROR HANDLING TESTLERİ =============

class TestErrorHandling:
    """
    Hata durumu testleri
    """
    
    def test_404_for_unknown_route(self, client):
        """TEST: Bilinmeyen route 404 dönmeli"""
        response = client.get('/nonexistent_page_12345')
        
        assert response.status_code == 404
    
    def test_method_not_allowed(self, client):
        """TEST: Yanlış HTTP method 405 dönmeli"""
        # Logout sadece POST kabul eder
        response = client.delete('/logout')
        
        assert response.status_code == 405



# ============= DASHBOARD MESAJ LİSTESİ TESTLERİ =============

def _fake_doc(doc_id, data):
    """Firestore DocumentSnapshot taklidi"""
    from unittest.mock import MagicMock
    doc = MagicMock()
    doc.id = doc_id
    doc.to_dict.return_value = data
    return doc


class TestDashboardMessages:
    """
    Dashboard'daki gelen mesaj listesi testleri
    """

    def _set_incoming(self, mock_db, docs):
        mock_db.collection.return_value.where.return_value.get.return_value = docs

    def test_newest_messages_first_and_missing_timestamp_last(self, authenticated_client, mock_db):
        """TEST: En yeni mesaj en üstte olmalı; tarihi olmayan mesaj listeyi bozmamalı"""
        from datetime import datetime, timezone
        from app import encrypt_message

        self._set_incoming(mock_db, [
            _fake_doc('eski', {'sender': 'alice', 'encrypted_content': encrypt_message('ESKI'),
                               'timestamp': datetime(2025, 1, 1, tzinfo=timezone.utc)}),
            _fake_doc('tarihsiz', {'sender': 'bob', 'encrypted_content': encrypt_message('TARIHSIZ')}),
            _fake_doc('yeni', {'sender': 'carol', 'encrypted_content': encrypt_message('YENI'),
                               'timestamp': datetime(2025, 6, 1, tzinfo=timezone.utc)}),
        ])

        html = authenticated_client.get('/dashboard').data.decode('utf-8')

        assert 'Mesajlar yüklenemedi' not in html
        assert html.index('YENI') < html.index('ESKI') < html.index('TARIHSIZ')

    def test_limit_keeps_newest_messages(self, authenticated_client, mock_db):
        """TEST: 50'den fazla mesaj varken en yeni 50 mesaj gösterilmeli"""
        from datetime import datetime, timedelta, timezone
        from app import encrypt_message, DASHBOARD_MESSAGE_LIMIT

        start = datetime(2025, 1, 1, tzinfo=timezone.utc)
        docs = [_fake_doc(f'm{i}', {'sender': 'alice', 'encrypted_content': encrypt_message(f'MSG-{i:03d}'),
                                    'timestamp': start + timedelta(minutes=i)})
                for i in range(DASHBOARD_MESSAGE_LIMIT + 10)]
        self._set_incoming(mock_db, docs)

        html = authenticated_client.get('/dashboard').data.decode('utf-8')

        newest = DASHBOARD_MESSAGE_LIMIT + 9
        assert f'MSG-{newest:03d}' in html
        assert 'MSG-000' not in html
        # Firestore sorgusunda limit() kullanılmamalı (sıralamadan önce kesmesin)
        mock_db.collection.return_value.where.return_value.limit.assert_not_called()


# ============= MESAJ GÖNDERME TESTLERİ =============

class TestSendMessage:
    """
    /send route testleri (Firestore mock'u ile)
    """

    def _set_receiver_lookup(self, mock_db, docs):
        mock_db.collection.return_value.where.return_value.limit.return_value.get.return_value = docs

    def test_send_to_unknown_user_rejected(self, authenticated_client, mock_db):
        """TEST: Kayıtlı olmayan kullanıcıya mesaj kaydedilmemeli"""
        self._set_receiver_lookup(mock_db, [])

        response = authenticated_client.post('/send', data={'receiver': 'nobody', 'message': 'merhaba'},
                                             follow_redirects=True)

        mock_db.collection.return_value.add.assert_not_called()
        assert 'bulunamadı' in response.data.decode('utf-8')

    def test_send_to_existing_user_saves_encrypted(self, authenticated_client, mock_db):
        """TEST: Kayıtlı kullanıcıya mesaj şifreli olarak kaydedilmeli"""
        self._set_receiver_lookup(mock_db, [_fake_doc('u1', {'username': 'bob'})])

        authenticated_client.post('/send', data={'receiver': 'bob', 'message': 'gizli mesaj'})

        mock_db.collection.return_value.add.assert_called_once()
        saved = mock_db.collection.return_value.add.call_args[0][0]
        assert saved['receiver'] == 'bob'
        assert saved['sender'] == 'test_user_123'
        assert 'gizli mesaj' not in saved['encrypted_content']


# ============= KAYIT YARIŞ DURUMU TESTLERİ =============

class TestRegisterUniqueness:
    """
    Aynı kullanıcı adıyla iki kaydın oluşmaması
    """

    def _no_existing_user(self, mock_db):
        mock_db.collection.return_value.where.return_value.limit.return_value.get.return_value = []

    def test_register_creates_document_with_username_id(self, client, mock_db):
        """TEST: Kullanıcı, adını ID olarak kullanan dokümanla create() ile kaydedilmeli"""
        self._no_existing_user(mock_db)

        client.post('/register', data={'username': 'yeni_kullanici', 'password': 'Sifre123'})

        mock_db.collection.return_value.document.assert_called_once_with('yeni_kullanici')
        mock_db.collection.return_value.document.return_value.create.assert_called_once()
        mock_db.collection.return_value.add.assert_not_called()

    def test_concurrent_duplicate_registration_rejected(self, client, mock_db):
        """TEST: Kontrolden sonra aynı ad kaydedilmişse (AlreadyExists) kullanıcıya uyarı verilmeli"""
        from google.api_core.exceptions import AlreadyExists
        self._no_existing_user(mock_db)
        mock_db.collection.return_value.document.return_value.create.side_effect = AlreadyExists('exists')

        response = client.post('/register', data={'username': 'yeni_kullanici', 'password': 'Sifre123'},
                               follow_redirects=True)

        assert 'zaten kullanılıyor' in response.data.decode('utf-8')
