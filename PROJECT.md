# 2071 Mektup — Proje Şeması

## Ana varlıklar
users, capsules, entries, media, family_members, participants, security_layers, audit_logs

## Kapsül durumları
DRAFT -> LOCKED -> OPEN

LOCKED kapsülün unlock_at değeri değiştirilemez. Sunucu zamanı unlock_at ile karşılaştırır.

## Görünürlük
PRIVATE / FAMILY / PUBLIC

PUBLIC kapsüllerin içeriği açılış tarihinden önce okunmaz; yalnızca izin verilen başlık, yıl, şehir ve açılış tarihi gibi metadata gösterilebilir. Tarih geldiğinde OPENED PUBLIC arşivine düşer.
