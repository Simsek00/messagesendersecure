import firebase_admin
from firebase_admin import credentials, firestore
from flask import Flask, request, jsonify

# 1. Firebase Bağlantısını Kur
# İndirdiğin JSON dosyasının adı buradakiyle AYNI olmalı!
cred = credentials.Certificate("serviceAccountKey.json")
firebase_admin.initialize_app(cred)

# Veritabanı istemcisini oluştur
db = firestore.client()

# 2. Flask Uygulamasını Başlat
app = Flask(__name__)

# Test Rotası (Sprint 1 Hedefi)
@app.route('/test', methods=['GET'])
def test_connection():
    try:
        # Veritabanına deneme verisi yazalım
        doc_ref = db.collection('test_logs').document('init_test')
        doc_ref.set({
            'durum': 'Baglanti Basarili',
            'mesaj': 'Merhaba Firebase!'
        })
        return jsonify({"status": "success", "message": "Firebase bağlantısı başarılı!"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)