import firebase_admin
from firebase_admin import credentials, firestore
import json
import datetime
import time
import schedule # pip install schedule

# Firebase Bağlantısı (Tekrar kuruyoruz çünkü bu ayrı çalışan bir script)
cred = credentials.Certificate("serviceAccountKey.json")
firebase_admin.initialize_app(cred)
db = firestore.client()

def yedek_al():
    print(f"Yedekleme basladi: {datetime.datetime.now()}")
    try:
        messages = db.collection('messages').stream()
        backup_data = []
        
        for msg in messages:
            msg_dict = msg.to_dict()
            # Timestamp nesnelerini stringe çevir (JSON hatası vermesin diye)
            if 'timestamp' in msg_dict and msg_dict['timestamp']:
                msg_dict['timestamp'] = str(msg_dict['timestamp'])
            backup_data.append(msg_dict)
            
        dosya_adi = f"backup_{datetime.datetime.now().strftime('%Y%m%d_%H%M')}.json"
        
        with open(dosya_adi, 'w', encoding='utf-8') as f:
            json.dump(backup_data, f, ensure_ascii=False, indent=4)
            
        print(f"Yedekleme basarili: {dosya_adi}")
    except Exception as e:
        print(f"Yedekleme hatasi: {e}")

# Test için hemen bir kere çalıştır
yedek_al()

# Normalde sunucuda sürekli çalışıp her gün yedek alır:
# schedule.every().day.at("23:59").do(yedek_al)
# while True:
#    schedule.run_pending()
#    time.sleep(60)