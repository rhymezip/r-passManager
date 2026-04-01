#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════╗
║                          r-pass                                  ║
║         Cross-Platform Local Password Manager                    ║
║                                                                  ║
║  Stack   : Python 3.9+ · PyQt5 · SQLite · AES-256-GCM            ║
║  KDF     : Argon2id (64MB, 3 iterations)                         ║
║  Compat  : macOS · Linux · Windows                               ║
║  i18n    : English · Türkçe · Русский                            ║
╚══════════════════════════════════════════════════════════════════╝
"""

# startup
import sys, os, subprocess, importlib

_REQUIRED = [
    ("PyQt5",    "PyQt5"),
    ("Crypto",   "pycryptodome"),
    ("pyperclip","pyperclip"),
]

# import satirlari
import sqlite3, secrets, string, hashlib, base64, json, re, platform
from datetime import datetime
from pathlib import Path
import platform

def get_emoji_font():
    system = platform.system()

    if system == "Windows":
        return "Segoe UI Emoji"
    elif system == "Darwin":
        return "Apple Color Emoji"
    elif system == "Linux":
        return "Noto Color Emoji"
    else:
        return "Sans-Serif"

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QDialog, QMessageBox,
    QFrame, QSlider, QSpinBox, QCheckBox, QTextEdit,
    QAbstractItemView, QShortcut, QStatusBar, QProgressBar,
    QFileDialog, QButtonGroup, QRadioButton, QScrollArea,
    QGraphicsOpacityEffect, QSizePolicy, QStackedWidget, QListWidget,
    QListWidgetItem, QSplitter, QAction, QMenu
)
from PyQt5.QtCore import (Qt, QTimer, QThread, pyqtSignal,
                           QPropertyAnimation, QEasingCurve,
                           QRect, QPoint, QSize, pyqtProperty, QObject)
from PyQt5.QtGui import (QFont, QColor, QKeySequence, QPainter,
                          QPainterPath, QLinearGradient, QBrush,
                          QPen, QPixmap, QIcon, QFontDatabase,
                          QCursor, QRegion)

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256, HMAC

try:
    import pyperclip; CLIP_AVAILABLE = True
except ImportError:
    CLIP_AVAILABLE = False

# paths

def get_data_dir() -> Path:
    if platform.system() == "Windows":
        base = Path(os.environ.get("APPDATA", Path.home()))
    elif platform.system() == "Darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    d = base / "r-pass"; d.mkdir(parents=True, exist_ok=True); return d

DATA_DIR      = get_data_dir()
DB_PATH       = DATA_DIR / "r-pass.db"
SETTINGS_PATH = DATA_DIR / "settings.json"

# settings

def load_settings() -> dict:
    try:
        if SETTINGS_PATH.exists():
            return json.loads(SETTINGS_PATH.read_text("utf-8"))
    except Exception: pass
    return {"lang": "en"}

def save_settings(data: dict):
    try: SETTINGS_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2), "utf-8")
    except Exception: pass

# i18n

TRANSLATIONS = {
    "en": {
        "lang_en": "🇺🇸  English", "lang_tr": "🇹🇷  Türkçe", "lang_ru": " 🇷🇺  Русский",
        "language": "Language", "select_language": "Select Language",
        "lang_restart_note": "Language updated.",
        "app_subtitle_unlock": "Enter your master password",
        "app_subtitle_setup": "Choose a master password",
        "master_warning": "This password protects all your records.\nIt cannot be recovered if forgotten.",
        "master_placeholder": "Master Password",
        "master_confirm_placeholder": "Confirm Password",
        "btn_create_vault": "Create Vault", "btn_unlock": "Unlock", "btn_cancel": "Cancel",
        "kdf_working": "Unlocking…",
        "err_min_chars": "At least 8 characters required.",
        "err_no_match": "Passwords don't match.",
        "err_empty": "Password cannot be empty.",
        "err_wrong_master": "Incorrect password",
        "all_entries": "All", "favorites": "Favorites",
        "backup": "Backup", "restore": "Restore", "lock": "Lock",
        "settings": "Settings",
        "entries_header": "Passwords",
        "search_placeholder": "Search…",
        "btn_new_entry": "New", "btn_generate": "Generate",
        "col_name": "Name", "col_url": "URL", "col_username": "Username",
        "col_password": "Password", "col_actions": "Actions",
        "n_entries": "{n} items",
        "dlg_add_entry": "New Password", "dlg_edit_entry": "Edit Password",
        "lbl_name": "Name", "lbl_url": "Website",
        "lbl_username": "Username", "lbl_password": "Password", "lbl_notes": "Notes",
        "ph_name": "e.g. GitHub", "ph_url": "https://",
        "ph_username": "you@example.com", "ph_password": "Password",
        "ph_notes": "Optional notes…",
        "btn_generate_short": "Generate", "btn_save": "Save",
        "btn_copy": "Copy", "btn_edit": "Edit", "btn_delete": "Delete",
        "btn_close": "Close",
        "err_name_required": "Name is required.",
        "err_pass_required": "Password is required.",
        "gen_title": "Password Generator", "lbl_length": "Length",
        "chk_upper": "A–Z", "chk_lower": "a–z",
        "chk_digits": "0–9", "chk_symbols": "!@#",
        "btn_use_password": "Use",
        "gen_entropy": "{n} chars · ~{e:.0f} bits entropy",
        "tip_copy_user": "Copy username",
        "tip_copy_pass": "Copy password",
        "tip_edit": "Edit", "tip_delete": "Delete",
        "status_added": "'{name}' added",
        "status_updated": "'{name}' updated",
        "status_deleted": "'{name}' deleted",
        "status_copy_user": "Username copied",
        "status_copy_pass": "Password copied — clears in 30s",
        "status_clip_cleared": "Clipboard cleared",
        "status_auto_locked": "Locked due to inactivity",
        "confirm_delete_title": "Delete Password",
        "confirm_delete_msg": "Delete '{name}'? This cannot be undone.",
        "backup_title": "Backup Vault",
        "backup_desc": "Export all passwords to an encrypted .r-pass file protected by your master password.",
        "backup_btn": "Save Backup",
        "backup_save_dialog": "Save Backup",
        "backup_filter": "r-pass Backup (*.r-pass)",
        "backup_success": "Backup saved to {path}",
        "backup_error": "Backup failed: {err}",
        "restore_title": "Restore from Backup",
        "restore_desc": "Select a .r-pass backup file and enter the master password used when the backup was created.",
        "restore_file_label": "Backup File",
        "restore_browse": "Browse",
        "restore_mode_label": "Import Mode",
        "restore_mode_merge": "Merge — keep existing, add from backup",
        "restore_mode_replace": "Replace — delete all, then import",
        "restore_btn": "Restore",
        "restore_open_dialog": "Open Backup File",
        "restore_filter": "r-pass Backup (*.r-pass)",
        "restore_err_no_file": "Please select a backup file.",
        "restore_err_bad_file": "Invalid or corrupted backup file.",
        "restore_err_wrong_pass": "Incorrect password for this backup.",
        "restore_success": "{n} passwords restored",
        "no_entries": "No passwords yet",
        "no_entries_sub": "Press New to add your first password",
        "username_label": "USERNAME",
        "password_label": "PASSWORD",
        "website_label": "WEBSITE",
        "notes_label": "NOTES",
        "created_label": "CREATED",
        "updated_label": "LAST UPDATED",
    },
    "tr": {
        "lang_en": "🇺🇸  English", "lang_tr": "🇹🇷  Türkçe", "lang_ru": " 🇷🇺  Русский",
        "language": "Dil", "select_language": "Dil Seç",
        "lang_restart_note": "Dil güncellendi.",
        "app_subtitle_unlock": "Master şifrenizi girin",
        "app_subtitle_setup": "Bir master şifre seçin",
        "master_warning": "Bu şifre tüm kayıtlarınızı korur.\nUnutulursa kurtarılamaz.",
        "master_placeholder": "Master Şifre",
        "master_confirm_placeholder": "Şifreyi Onayla",
        "btn_create_vault": "Vault Oluştur", "btn_unlock": "Aç", "btn_cancel": "İptal",
        "kdf_working": "Açılıyor…",
        "err_min_chars": "En az 8 karakter gerekli.",
        "err_no_match": "Şifreler eşleşmiyor.",
        "err_empty": "Şifre boş olamaz.",
        "err_wrong_master": "Yanlış şifre",
        "all_entries": "Tümü", "favorites": "Favoriler",
        "backup": "Yedekle", "restore": "Geri Yükle", "lock": "Kilitle",
        "settings": "Ayarlar",
        "entries_header": "Şifreler",
        "search_placeholder": "Ara…",
        "btn_new_entry": "Yeni", "btn_generate": "Üret",
        "col_name": "Ad", "col_url": "URL", "col_username": "Kullanıcı",
        "col_password": "Şifre", "col_actions": "İşlemler",
        "n_entries": "{n} kayıt",
        "dlg_add_entry": "Yeni Şifre", "dlg_edit_entry": "Şifreyi Düzenle",
        "lbl_name": "Ad", "lbl_url": "Website",
        "lbl_username": "Kullanıcı Adı", "lbl_password": "Şifre", "lbl_notes": "Notlar",
        "ph_name": "örn. GitHub", "ph_url": "https://",
        "ph_username": "siz@ornek.com", "ph_password": "Şifre",
        "ph_notes": "İsteğe bağlı notlar…",
        "btn_generate_short": "Üret", "btn_save": "Kaydet",
        "btn_copy": "Kopyala", "btn_edit": "Düzenle", "btn_delete": "Sil",
        "btn_close": "Kapat",
        "err_name_required": "Ad zorunludur.",
        "err_pass_required": "Şifre zorunludur.",
        "gen_title": "Şifre Üretici", "lbl_length": "Uzunluk",
        "chk_upper": "A–Z", "chk_lower": "a–z",
        "chk_digits": "0–9", "chk_symbols": "!@#",
        "btn_use_password": "Kullan",
        "gen_entropy": "{n} karakter · ~{e:.0f} bit entropi",
        "tip_copy_user": "Kullanıcı adını kopyala",
        "tip_copy_pass": "Şifreyi kopyala",
        "tip_edit": "Düzenle", "tip_delete": "Sil",
        "status_added": "'{name}' eklendi",
        "status_updated": "'{name}' güncellendi",
        "status_deleted": "'{name}' silindi",
        "status_copy_user": "Kullanıcı adı kopyalandı",
        "status_copy_pass": "Şifre kopyalandı — 30s sonra temizlenir",
        "status_clip_cleared": "Pano temizlendi",
        "status_auto_locked": "Hareketsizlik nedeniyle kilitlendi",
        "confirm_delete_title": "Şifreyi Sil",
        "confirm_delete_msg": "'{name}' silinsin mi? Bu geri alınamaz.",
        "backup_title": "Vault'u Yedekle",
        "backup_desc": "Tüm şifreler, master şifrenizle korunan şifreli bir .r-pass dosyasına aktarılır.",
        "backup_btn": "Yedeği Kaydet",
        "backup_save_dialog": "Yedeği Kaydet",
        "backup_filter": "r-pass Yedek (*.r-pass)",
        "backup_success": "Yedek {path} konumuna kaydedildi",
        "backup_error": "Yedekleme başarısız: {err}",
        "restore_title": "Yedekten Geri Yükle",
        "restore_desc": "Bir .r-pass yedek dosyası seçin ve yedek oluşturulurken kullanılan master şifreyi girin.",
        "restore_file_label": "Yedek Dosyası",
        "restore_browse": "Gözat",
        "restore_mode_label": "İçe Aktarma Modu",
        "restore_mode_merge": "Birleştir — mevcut kayıtları koru, yedekten ekle",
        "restore_mode_replace": "Değiştir — hepsini sil, sonra aktar",
        "restore_btn": "Geri Yükle",
        "restore_open_dialog": "Yedek Dosyası Aç",
        "restore_filter": "r-pass Yedek (*.r-pass)",
        "restore_err_no_file": "Lütfen bir yedek dosyası seçin.",
        "restore_err_bad_file": "Geçersiz veya bozuk yedek dosyası.",
        "restore_err_wrong_pass": "Bu yedek için şifre yanlış.",
        "restore_success": "{n} şifre geri yüklendi",
        "no_entries": "Henüz şifre yok",
        "no_entries_sub": "İlk şifrenizi eklemek için Yeni'ye basın",
        "username_label": "KULLANICI ADI",
        "password_label": "ŞİFRE",
        "website_label": "WEBSİTE",
        "notes_label": "NOTLAR",
        "created_label": "OLUŞTU🇷LMA",
        "updated_label": "SON GÜNCELLEME",
    },
    "ru": {
        "lang_en": "🇺🇸  English", "lang_tr": "🇹🇷  Türkçe", "lang_ru": " 🇷🇺  Русский",
        "language": "Язык", "select_language": "Выбор языка",
        "lang_restart_note": "Язык обновлён.",
        "app_subtitle_unlock": "Введите мастер-пароль",
        "app_subtitle_setup": "Создайте мастер-пароль",
        "master_warning": "Этот пароль защищает все ваши записи.\nЕсли забудете — восстановление невозможно.",
        "master_placeholder": "Мастер-пароль",
        "master_confirm_placeholder": "Подтвердите пароль",
        "btn_create_vault": "Создать хранилище", "btn_unlock": "Открыть", "btn_cancel": "Отмена",
        "kdf_working": "Открывается…",
        "err_min_chars": "Минимум 8 символов.",
        "err_no_match": "Пароли не совпадают.",
        "err_empty": "Пароль не может быть пустым.",
        "err_wrong_master": "Неверный пароль",
        "all_entries": "Все", "favorites": "Избранное",
        "backup": "Резервная копия", "restore": "Восстановить", "lock": "Заблокировать",
        "settings": "Настройки",
        "entries_header": "Пароли",
        "search_placeholder": "Поиск…",
        "btn_new_entry": "Новый", "btn_generate": "Генератор",
        "col_name": "Имя", "col_url": "URL", "col_username": "Пользователь",
        "col_password": "Пароль", "col_actions": "Действия",
        "n_entries": "{n} записей",
        "dlg_add_entry": "Новый пароль", "dlg_edit_entry": "Редактировать пароль",
        "lbl_name": "Имя", "lbl_url": "Сайт",
        "lbl_username": "Имя пользователя", "lbl_password": "Пароль", "lbl_notes": "Заметки",
        "ph_name": "напр. GitHub", "ph_url": "https://",
        "ph_username": "you@example.com", "ph_password": "Пароль",
        "ph_notes": "Необязательные заметки…",
        "btn_generate_short": "Создать", "btn_save": "Сохранить",
        "btn_copy": "Копировать", "btn_edit": "Изменить", "btn_delete": "Удалить",
        "btn_close": "Закрыть",
        "err_name_required": "Имя обязательно.",
        "err_pass_required": "Пароль обязателен.",
        "gen_title": "Генератор паролей", "lbl_length": "Длина",
        "chk_upper": "A–Z", "chk_lower": "a–z",
        "chk_digits": "0–9", "chk_symbols": "!@#",
        "btn_use_password": "Использовать",
        "gen_entropy": "{n} симв · ~{e:.0f} бит энтропии",
        "tip_copy_user": "Копировать имя пользователя",
        "tip_copy_pass": "Копировать пароль",
        "tip_edit": "Редактировать", "tip_delete": "Удалить",
        "status_added": "'{name}' добавлено",
        "status_updated": "'{name}' обновлено",
        "status_deleted": "'{name}' удалено",
        "status_copy_user": "Имя пользователя скопировано",
        "status_copy_pass": "Пароль скопирован — очистится через 30с",
        "status_clip_cleared": "Буфер обмена очищен",
        "status_auto_locked": "Заблокировано из-за бездействия",
        "confirm_delete_title": "Удалить пароль",
        "confirm_delete_msg": "Удалить '{name}'? Это необратимо.",
        "backup_title": "Резервная копия",
        "backup_desc": "Все пароли будут экспортированы в зашифрованный файл .r-pass.",
        "backup_btn": "Сохранить копию",
        "backup_save_dialog": "Сохранить резервную копию",
        "backup_filter": "Резервная копия r-pass (*.r-pass)",
        "backup_success": "Копия сохранена в {path}",
        "backup_error": "Ошибка резервного копирования: {err}",
        "restore_title": "Восстановить из копии",
        "restore_desc": "Выберите файл .r-pass и введите мастер-пароль, использованный при создании копии.",
        "restore_file_label": "Файл резервной копии",
        "restore_browse": "Обзор",
        "restore_mode_label": "Режим импорта",
        "restore_mode_merge": "Объединить — сохранить существующие, добавить из копии",
        "restore_mode_replace": "Заменить — удалить всё, затем импортировать",
        "restore_btn": "Восстановить",
        "restore_open_dialog": "Открыть файл резервной копии",
        "restore_filter": "Резервная копия r-pass (*.r-pass)",
        "restore_err_no_file": "Пожалуйста, выберите файл резервной копии.",
        "restore_err_bad_file": "Недействительный или повреждённый файл.",
        "restore_err_wrong_pass": "Неверный пароль для этого файла.",
        "restore_success": "Восстановлено {n} паролей",
        "no_entries": "Паролей пока нет",
        "no_entries_sub": "Нажмите «Новый», чтобы добавить первый пароль",
        "username_label": "ИМЯ ПОЛЬЗОВАТЕЛЯ",
        "password_label": "ПАРОЛЬ",
        "website_label": "САЙТ",
        "notes_label": "ЗАМЕТКИ",
        "created_label": "СОЗДАНО",
        "updated_label": "ОБНОВЛЕНО",
    },
}

_current_lang = "en"

def set_lang(lang: str):
    global _current_lang
    if lang in TRANSLATIONS: _current_lang = lang

def t(key: str, **kwargs) -> str:
    s = TRANSLATIONS.get(_current_lang, TRANSLATIONS["en"]).get(key, key)
    if kwargs:
        try: s = s.format(**kwargs)
        except Exception: pass
    return s

# crypto

# Argon2id Parametreleri (Modern Güvenlik Standardı)

try:
    from argon2 import low_level
except ImportError:
    pass

PBKDF2_DKLEN = 32
SALT_SIZE = 32

def derive_key(master_password: str, salt: bytes) -> bytes:
    # Argon2id: PBKDF2
    return low_level.hash_secret_raw(
        secret=master_password.encode("utf-8"),
        salt=salt,
        time_cost=3,          # İterasyon sayısı
        memory_cost=65536,    # Bellek kullanımı (64MB)
        parallelism=4,        # Paralel işlem
        hash_len=32,
        type=low_level.Type.ID
    )

def key_fingerprint(key: bytes) -> bytes:
    return hashlib.sha256(key).digest()

# AES-GCM (Authenticated Encryption) kullanımı
def encrypt_field(key: bytes, plaintext: str) -> str:
    nonce = secrets.token_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
    return base64.b64encode(nonce + tag + ciphertext).decode('utf-8')

def decrypt_field(key: bytes, token: str) -> str:
    try:
        raw = base64.b64decode(token.encode('utf-8'))
        nonce, tag, ciphertext = raw[:12], raw[12:28], raw[28:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
    except:
        return None

SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?~"

def generate_password(length=20, use_upper=True, use_lower=True,
                      use_digits=True, use_symbols=True) -> str:
    if length < 4: length = 4
    alpha = ""; req = []
    if use_upper:   alpha += string.ascii_uppercase; req.append(secrets.choice(string.ascii_uppercase))
    if use_lower:   alpha += string.ascii_lowercase; req.append(secrets.choice(string.ascii_lowercase))
    if use_digits:  alpha += string.digits;          req.append(secrets.choice(string.digits))
    if use_symbols: alpha += SYMBOLS;               req.append(secrets.choice(SYMBOLS))
    if not alpha:   alpha = string.ascii_letters + string.digits; req = [secrets.choice(alpha)]
    pool = req + [secrets.choice(alpha) for _ in range(length - len(req))]
    for i in range(len(pool)-1, 0, -1):
        j = secrets.randbelow(i+1); pool[i], pool[j] = pool[j], pool[i]
    return "".join(pool)

def password_strength(password: str):
    if not password: return 0, ""
    s = 0
    for threshold, score in [(8,10),(12,10),(16,10),(20,10)]:
        if len(password) >= threshold: s += score
    if re.search(r'[A-Z]', password): s += 15
    if re.search(r'[a-z]', password): s += 15
    if re.search(r'\d', password):    s += 15
    if re.search(r'[^A-Za-z0-9]', password): s += 15
    if s < 30: return s, "weak"
    if s < 60: return s, "fair"
    if s < 80: return s, "good"
    return s, "strong"

STRENGTH_COLORS = {
    "weak": "#FF453A", "fair": "#FF9F0A",
    "good": "#30D158", "strong": "#0A84FF", "": "#333"
}

# local database

class Database:
    def __init__(self, path: Path = DB_PATH):
        self.path = str(path); self._init()

    def _conn(self):
        c = sqlite3.connect(self.path); c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL"); c.execute("PRAGMA foreign_keys=ON"); return c

    def _init(self):
        with self._conn() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS meta (
                id INTEGER PRIMARY KEY, salt BLOB NOT NULL,
                key_check BLOB NOT NULL, created_at TEXT NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                enc_data TEXT NOT NULL)""")

            cols = [r[1] for r in db.execute("PRAGMA table_info(meta)").fetchall()]
            if "label" not in cols:
                db.execute("ALTER TABLE meta ADD COLUMN label TEXT DEFAULT 'My Vault'")

    def is_initialized(self) -> bool:
        with self._conn() as db:
            return db.execute("SELECT 1 FROM meta LIMIT 1").fetchone() is not None

    def setup(self, master_password: str, label: str = "r-pass") -> bytes:
        salt = secrets.token_bytes(SALT_SIZE); key = derive_key(master_password, salt)
        with self._conn() as db:
            db.execute("DELETE FROM meta")
            db.execute("INSERT INTO meta VALUES(1,?,?,?,?)",
                       (salt, key_fingerprint(key), datetime.utcnow().isoformat(), label))
        return key

    def verify(self, master_password: str):
        with self._conn() as db:
            row = db.execute("SELECT salt, key_check FROM meta WHERE id=1").fetchone()
        if not row: return None
        key = derive_key(master_password, bytes(row["salt"]))
        return key if key_fingerprint(key) == bytes(row["key_check"]) else None

    def get_label(self) -> str:
        with self._conn() as db:
            row = db.execute("SELECT label FROM meta WHERE id=1").fetchone()
            return row["label"] if row else "Vault"

    def set_label(self, label: str):
        with self._conn() as db:
            db.execute("UPDATE meta SET label=? WHERE id=1", (label,))

    def list_entries(self, key: bytes, query: str = "") -> list:
        with self._conn() as db:
            rows = db.execute("SELECT id, enc_data FROM entries").fetchall()
        q = query.lower(); result = []
        for r in rows:
            try:
                plain_json = decrypt_field(key, r["enc_data"])
                if not plain_json: continue
                data = json.loads(plain_json)
                if q:
                    search_str = f"{data.get('name','')}{data.get('url','')}{data.get('username','')}".lower()
                    if q not in search_str: continue
                data["id"] = r["id"]
                result.append(data)
            except: continue
        return sorted(result, key=lambda x: x.get('name','').lower())

    def add_entry(self, key, name, url, username, password, notes) -> int:
        now = datetime.utcnow().isoformat()
        payload = json.dumps({
            "name": name, "url": url, "username": username,
            "password": password, "notes": notes,
            "created_at": now, "updated_at": now
        })
        enc = encrypt_field(key, payload)
        with self._conn() as db:
            cur = db.execute("INSERT INTO entries(enc_data) VALUES(?)", (enc,))
            return cur.lastrowid

    def update_entry(self, key, eid, name, url, username, password, notes):
        now = datetime.utcnow().isoformat()
        payload = json.dumps({
            "name": name, "url": url, "username": username,
            "password": password, "notes": notes, "updated_at": now
        })
        enc = encrypt_field(key, payload)
        with self._conn() as db:
            db.execute("UPDATE entries SET enc_data=? WHERE id=?", (enc, eid))

    def delete_entry(self, eid: int):
        with self._conn() as db: db.execute("DELETE FROM entries WHERE id=?", (eid,))

    def delete_all_entries(self):
        with self._conn() as db: db.execute("DELETE FROM entries")

    def export_backup(self, key: bytes, path: str):
        entries = self.list_entries(key)
        payload = json.dumps({
            "version": "3.0",
            "exported_at": datetime.utcnow().isoformat(),
            "entries": entries
        }, ensure_ascii=False)
        salt = secrets.token_bytes(SALT_SIZE)
        bkkey = derive_key(base64.b64encode(key).decode("ascii"), salt)
        enc_blob = encrypt_field(bkkey, payload)
        final = base64.b64encode(salt + base64.b64decode(enc_blob))
        with open(path, "wb") as f:
            f.write(b"r-pass-v3\n" + final + b"\n")

    def import_backup(self, key: bytes, path: str, replace: bool = False) -> int:
        with open(path, "rb") as f: lines = f.read().split(b"\n")
        if lines[0] != b"r-pass-v3": raise ValueError("invalid_file")
        blob = base64.b64decode(lines[1])
        salt, enc_data = blob[:SALT_SIZE], base64.b64encode(blob[SALT_SIZE:]).decode('utf-8')
        bkkey = derive_key(base64.b64encode(key).decode("ascii"), salt)
        plain = decrypt_field(bkkey, enc_data)
        if not plain: raise ValueError("wrong_pass")
        data = json.loads(plain); entries = data.get("entries", [])
        if replace: self.delete_all_entries()
        for e in entries:
            self.add_entry(key, e['name'], e.get('url',''), e.get('username',''), e['password'], e.get('notes',''))
        return len(entries)

# theme
C = {
    "bg":        "#000000",
    "bg1":       "#0A0A0A",
    "bg2":       "#111111",
    "bg3":       "#1A1A1A",
    "bg4":       "#222222",
    "border":    "#2A2A2A",
    "border2":   "#333333",
    "text":      "#FFFFFF",
    "text2":     "#EBEBEB",
    "text3":     "#8E8E93",
    "text4":     "#48484A",
    "accent":    "#0A84FF",
    "accent2":   "#0066CC",
    "green":     "#30D158",
    "red":       "#FF453A",
    "yellow":    "#FF9F0A",
    "purple":    "#BF5AF2",
}

QSS = f"""
QWidget {{
    background-color: {C['bg']};
    color: {C['text2']};
    font-family: ".AppleSystemUIFont", "Helvetica Neue", Arial;
    font-size: 13px;
}}
QMainWindow {{ background-color: {C['bg']}; }}

QPushButton {{
    background-color: {C['accent']};
    color: #FFFFFF;
    border: none;
    border-radius: 8px;
    padding: 8px 18px;
    font-size: 13px;
    font-weight: 600;
}}
QPushButton:hover {{ background-color: {C['accent2']}; }}
QPushButton:pressed {{ background-color: #004499; }}
QPushButton:disabled {{ background-color: {C['bg3']}; color: {C['text4']}; }}

QPushButton#secondary {{
    background-color: {C['bg3']};
    color: {C['text2']};
    border: 1px solid {C['border']};
}}
QPushButton#secondary:hover {{
    background-color: {C['bg4']};
    border-color: {C['border2']};
}}

QPushButton#ghost {{
    background-color: transparent;
    color: {C['text3']};
    border: none;
    padding: 6px 12px;
    font-weight: 500;
}}
QPushButton#ghost:hover {{ color: {C['text']}; background-color: {C['bg3']}; }}

QPushButton#icon_btn {{
    background-color: transparent;
    border: none;
    padding: 4px 8px;
    border-radius: 6px;
    color: {C['text4']};
    font-size: 14px;
}}
QPushButton#icon_btn:hover {{
    color: {C['accent']};
    background-color: {C['bg3']};
}}

QPushButton#danger {{
    background-color: transparent;
    color: {C['red']};
    border: none;
    padding: 6px 12px;
}}
QPushButton#danger:hover {{ background-color: rgba(255,69,58,0.1); }}

QLineEdit, QTextEdit {{
    background-color: {C['bg2']};
    color: {C['text']};
    border: 1px solid {C['border']};
    border-radius: 8px;
    padding: 9px 13px;
    font-size: 14px;
    selection-background-color: {C['accent']};
}}
QLineEdit:focus, QTextEdit:focus {{
    border-color: {C['accent']};
    background-color: {C['bg2']};
    outline: none;
}}
QLineEdit::placeholder {{ color: {C['text4']}; }}

QScrollArea {{ border: none; background: transparent; }}
QScrollBar:vertical {{
    background: transparent;
    width: 4px;
    border-radius: 2px;
}}
QScrollBar::handle:vertical {{
    background: {C['bg4']};
    border-radius: 2px;
    min-height: 24px;
}}
QScrollBar::handle:vertical:hover {{ background: {C['border2']}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{ background: none; }}

QCheckBox {{ color: {C['text3']}; spacing: 8px; background: transparent; border: none; }}
QCheckBox::indicator {{
    width: 17px; height: 17px;
    border-radius: 5px;
    border: 1.5px solid {C['border2']};
    background: {C['bg2']};
}}
QCheckBox::indicator:checked {{
    background: {C['accent']};
    border-color: {C['accent']};
}}

QRadioButton {{ color: {C['text3']}; spacing: 8px; }}
QRadioButton::indicator {{
    width: 16px; height: 16px;
    border-radius: 8px;
    border: 1.5px solid {C['border2']};
    background: {C['bg2']};
}}
QRadioButton::indicator:checked {{
    background: {C['accent']};
    border-color: {C['accent']};
}}

QProgressBar {{
    background-color: {C['bg3']};
    border-radius: 2px;
    border: none;
    height: 3px;
}}
QProgressBar::chunk {{ background-color: {C['accent']}; border-radius: 2px; }}

QSlider {{
    background: transparent;
}}
QSlider::groove:horizontal {{
    height: 4px;
    background: {C['bg3']};
    border-radius: 2px;
}}
QSlider::handle:horizontal {{
    width: 16px; height: 16px;
    background: {C['accent']};
    border-radius: 8px;
    margin: -6px 0;
}}
QSlider::sub-page:horizontal {{
    background: {C['accent']};
    border-radius: 2px;
}}

QSpinBox {{
    background-color: {C['bg2']};
    color: {C['text']};
    border: 1px solid {C['border']};
    border-radius: 6px;
    padding: 5px 8px;
}}
QSpinBox::up-button, QSpinBox::down-button {{ width: 0; }}

QDialog {{ background-color: {C['bg1']}; border: none; }}

QToolTip {{
    background-color: {C['bg3']};
    color: {C['text']};
    border: 1px solid {C['border2']};
    border-radius: 6px;
    padding: 5px 9px;
    font-size: 12px;
}}

QStatusBar {{
    background-color: {C['bg']};
    color: {C['text4']};
    font-size: 11px;
    border-top: 1px solid {C['bg2']};
}}
"""

# widgets

class FadeWidget(QWidget):
    """Widget that fades in on show"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self._opacity = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self._opacity)
        self._opacity.setOpacity(0)

    def fade_in(self, duration=200):
        anim = QPropertyAnimation(self._opacity, b"opacity", self)
        anim.setDuration(duration)
        anim.setStartValue(0.0)
        anim.setEndValue(1.0)
        anim.setEasingCurve(QEasingCurve.OutCubic)
        anim.start(QPropertyAnimation.DeleteWhenStopped)

    def fade_out(self, duration=150, on_done=None):
        anim = QPropertyAnimation(self._opacity, b"opacity", self)
        anim.setDuration(duration)
        anim.setStartValue(1.0)
        anim.setEndValue(0.0)
        anim.setEasingCurve(QEasingCurve.InCubic)
        if on_done: anim.finished.connect(on_done)
        anim.start(QPropertyAnimation.DeleteWhenStopped)

class StrengthBar(QWidget):
    """Minimal 4-segment strength indicator"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(3)
        self._score = 0
        self._label = ""

    def set_strength(self, score, label):
        self._score = score
        self._label = label
        self.update()

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w = self.width(); h = self.height()
        gap = 3; seg = (w - gap * 3) // 4
        color = QColor(STRENGTH_COLORS.get(self._label, C['bg4']))
        off_color = QColor(C['bg4'])
        seg_count = 0
        if self._score >= 30: seg_count = 1
        if self._score >= 50: seg_count = 2
        if self._score >= 70: seg_count = 3
        if self._score >= 85: seg_count = 4
        for i in range(4):
            x = i * (seg + gap)
            c = color if i < seg_count else off_color
            p.setBrush(QBrush(c)); p.setPen(Qt.NoPen)
            path = QPainterPath()
            path.addRoundedRect(x, 0, seg, h, 1.5, 1.5)
            p.drawPath(path)

# kdf worker

class KDFWorker(QThread):
    finished = pyqtSignal(object)
    def __init__(self, db, password, mode):
        super().__init__(); self.db=db; self.password=password; self.mode=mode
    def run(self):
        try:
            key = self.db.setup(self.password) if self.mode=="setup" else self.db.verify(self.password)
            self.finished.emit(key)
        except Exception as e:
            print(f"[KDF] {e}"); self.finished.emit(None)

# icon helper

def entry_avatar(name: str) -> str:
    """Return 1–2 char initials for an entry"""
    name = name.strip()
    if not name: return "?"
    words = name.split()
    if len(words) >= 2: return (words[0][0] + words[1][0]).upper()
    return name[:2].upper() if len(name) >= 2 else name[0].upper()

# Map common service names to color hues (deterministic)
def avatar_color(name: str) -> str:
    colors = [
        "#0A84FF", "#30D158", "#FF9F0A", "#BF5AF2",
        "#FF453A", "#64D2FF", "#FFD60A", "#FF6961",
        "#5E5CE6", "#AC8E68",
    ]
    idx = sum(ord(c) for c in name.lower()) % len(colors)
    return colors[idx]

# login LoginScreen

class LoginScreen(QDialog):
    """Clean, minimal login — no clutter, immediate unlock"""
    def __init__(self, db, mode="unlock", parent=None):
        super().__init__(parent)
        self.db = db; self.mode = mode; self.key = None
        self.setWindowFlags(Qt.Dialog | Qt.FramelessWindowHint)
        self.setFixedSize(400, 340 if mode == "setup" else 280)
        self.setModal(True)
        self.setAttribute(Qt.WA_TranslucentBackground, False)
        self._build()
        self._update_mask()

    def _update_mask(self):
        from PyQt5.QtCore import QRectF as QRF
        rect = QRF(0, 0, self.width(), self.height())
        radius = 20
        path = QPainterPath()
        path.addRoundedRect(rect, radius, radius)
        self.setMask(QRegion(path.toFillPolygon().toPolygon()))

    def _build(self):
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {C['bg1']};
                border: none;
                border-radius: 20px;
            }}
        """)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(40, 36, 40, 36)
        lay.setSpacing(0)

        top = QHBoxLayout()
        close_btn = QPushButton("✕")
        close_btn.setObjectName("ghost")
        close_btn.setFixedSize(30, 30)
        close_btn.setStyleSheet(f"QPushButton{{background:transparent;border:none;color:{C['text3']};font-size:14px;}}"
                               f"QPushButton:hover{{color:{C['text']};background:{C['bg3']};border-radius:6px;}}")
        close_btn.clicked.connect(self.reject)
        top.addWidget(close_btn)
        top.addStretch()
        lang_btn = QPushButton(" 🌐 ")
        lang_btn.setObjectName("ghost")
        lang_btn.setFixedSize(40, 40)
        lang_btn.setStyleSheet(f"QPushButton{{background:transparent;border:none;color:{C['text3']};font-size:16px;}}"
                               f"QPushButton:hover{{color:{C['text']};background:{C['bg3']};border-radius:6px;}}")
        lang_btn.clicked.connect(self._open_lang)
        top.addWidget(lang_btn)
        lay.addLayout(top)
        lay.addSpacing(24)

        # title
        self.title = QLabel("r-pass")
        self.title.setStyleSheet(f"color: {C['text']}; font-size: 22px; font-weight: 700; background: transparent; letter-spacing: -0.5px;")
        lay.addWidget(self.title)
        lay.addSpacing(4)

        self.sub = QLabel(t(f"app_subtitle_{self.mode}"))
        self.sub.setStyleSheet(f"color: {C['text3']}; font-size: 13px; background: transparent;")
        lay.addWidget(self.sub)
        lay.addSpacing(24)

        # password field
        self.pw = QLineEdit()
        self.pw.setPlaceholderText(t("master_placeholder"))
        self.pw.setEchoMode(QLineEdit.Password)
        self.pw.setFixedHeight(44)
        self.pw.setStyleSheet(f"""
            QLineEdit {{
                background: {C['bg3']};
                border: 1px solid {C['border']};
                border-radius: 10px;
                color: {C['text']};
                font-size: 15px;
                padding: 0 14px;
                letter-spacing: 1px;
            }}
            QLineEdit:focus {{ border-color: {C['accent']}; }}
        """)
        lay.addWidget(self.pw)

        if self.mode == "setup":
            lay.addSpacing(8)
            self.pw2 = QLineEdit()
            self.pw2.setPlaceholderText(t("master_confirm_placeholder"))
            self.pw2.setEchoMode(QLineEdit.Password)
            self.pw2.setFixedHeight(44)
            self.pw2.setStyleSheet(self.pw.styleSheet())
            lay.addWidget(self.pw2)

        lay.addSpacing(6)

        # error label
        self.errlbl = QLabel("")
        self.errlbl.setStyleSheet(f"color: {C['red']}; font-size: 12px; background: transparent;")
        self.errlbl.setFixedHeight(18)
        lay.addWidget(self.errlbl)
        lay.addSpacing(10)

        # action button
        label = t("btn_create_vault") if self.mode == "setup" else t("btn_unlock")
        self.okb = QPushButton(label)
        self.okb.setFixedHeight(44)
        self.okb.setStyleSheet(f"""
            QPushButton {{
                background: {C['accent']};
                color: white;
                border-radius: 10px;
                font-size: 15px;
                font-weight: 600;
                border: none;
            }}
            QPushButton:hover {{ background: {C['accent2']}; }}
            QPushButton:disabled {{ background: {C['bg4']}; color: {C['text4']}; }}
        """)
        self.okb.clicked.connect(self._proceed)
        self.okb.setDefault(True)
        lay.addWidget(self.okb)

        self.pw.returnPressed.connect(self._proceed)
        if self.mode == "setup" and hasattr(self, "pw2"):
            self.pw2.returnPressed.connect(self._proceed)

        self.pw.setFocus()

    def _open_lang(self):
        dlg = LanguageDialog(self)
        if dlg.exec_() == QDialog.Accepted:
            self.sub.setText(t(f"app_subtitle_{self.mode}"))
            self.okb.setText(t("btn_create_vault") if self.mode == "setup" else t("btn_unlock"))
            self.pw.setPlaceholderText(t("master_placeholder"))
            if self.mode == "setup" and hasattr(self, "pw2"):
                self.pw2.setPlaceholderText(t("master_confirm_placeholder"))

    def _proceed(self):
        pw = self.pw.text()
        if self.mode == "setup":
            if len(pw) < 8: self.errlbl.setText(t("err_min_chars")); return
            if pw != self.pw2.text(): self.errlbl.setText(t("err_no_match")); return
        if not pw: self.errlbl.setText(t("err_empty")); return

        self.errlbl.setText("")
        self.okb.setEnabled(False)
        self.okb.setText(t("kdf_working"))

        self.worker = KDFWorker(self.db, pw, self.mode)
        self.worker.finished.connect(self._done)
        self.worker.start()

    def _done(self, key):
        self.okb.setEnabled(True)
        label = t("btn_create_vault") if self.mode == "setup" else t("btn_unlock")
        self.okb.setText(label)
        if key is None:
            self.errlbl.setText(t("err_wrong_master"))
            self.pw.clear(); self.pw.setFocus()
        else:
            self.key = key; self.accept()

# language

class LanguageDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.selected = _current_lang
        self.setWindowFlags(Qt.Dialog | Qt.FramelessWindowHint)
        self.setFixedSize(320, 260)
        self.setModal(True)
        self._build()
        self._apply_mask()

    def _apply_mask(self):
        from PyQt5.QtCore import QRectF as QRF
        rect = QRF(0, 0, self.width(), self.height())
        radius = 20
        path = QPainterPath()
        path.addRoundedRect(rect, radius, radius)
        self.setMask(QRegion(path.toFillPolygon().toPolygon()))

    def _build(self):
        self.setStyleSheet(QSS + f"""
            QDialog {{
                background: {C['bg1']};
                border-radius: 16px;
            }}
        """)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        header = QWidget()
        header.setFixedHeight(56)
        header.setStyleSheet(f"background: {C['bg1']}; border-top-left-radius: 16px; border-top-right-radius: 16px;")
        hl = QHBoxLayout(header)
        hl.setContentsMargins(20, 0, 16, 0)

        close_btn = QPushButton("✕")
        close_btn.setObjectName("ghost")
        close_btn.setFixedSize(30, 30)
        close_btn.setStyleSheet(f"QPushButton{{background:transparent;border:none;color:{C['text3']};font-size:14px;}}"
                               f"QPushButton:hover{{color:{C['text']};background:{C['bg3']};border-radius:6px;}}")
        close_btn.clicked.connect(self.reject)
        hl.addWidget(close_btn)
        hl.addStretch()

        title = QLabel(t("select_language"))
        title.setStyleSheet(f"color:{C['text']};font-size:16px;font-weight:700;background:transparent;")
        hl.addWidget(title)
        hl.addStretch()
        lay.addWidget(header)

        content = QWidget()
        content.setStyleSheet(f"background: {C['bg1']};")
        cl = QVBoxLayout(content)
        cl.setContentsMargins(24, 20, 24, 20)
        cl.setSpacing(14)

        self._grp = QButtonGroup(self)
        for code in ("en", "tr", "ru"):
            rb = QRadioButton(t(f"lang_{code}"))
            rb.setChecked(code == _current_lang)
            rb.setStyleSheet(f"""
                QRadioButton {{
                    color: {C['text2']};
                    font-size: 14px;
                    padding: 8px 12px;
                    border-radius: 8px;
                    background: transparent;
                }}
                QRadioButton:hover {{ background: {C['bg3']}; }}
                QRadioButton::indicator {{ width:16px;height:16px;border-radius:8px;
                    border:1.5px solid {C['border2']};background:{C['bg2']}; }}
                QRadioButton::indicator:checked {{
                    background: {C['accent']}; border-color: {C['accent']}; }}
            """)
            rb.setProperty("lc", code)
            self._grp.addButton(rb); cl.addWidget(rb)

        cl.addStretch()
        row = QHBoxLayout(); row.setSpacing(8)
        c = QPushButton(t("btn_cancel")); c.setObjectName("secondary")
        c.setFixedHeight(38); c.clicked.connect(self.reject)
        ok = QPushButton("OK"); ok.setFixedHeight(38)
        ok.clicked.connect(self._apply); ok.setDefault(True)
        row.addWidget(c); row.addWidget(ok)
        cl.addLayout(row)

        lay.addWidget(content)

    def _apply(self):
        for b in self._grp.buttons():
            if b.isChecked(): self.selected = b.property("lc"); break
        set_lang(self.selected)
        cfg = load_settings(); cfg["lang"] = self.selected; save_settings(cfg)
        self.accept()

# list item widget

class EntryCardWidget(QWidget):
    clicked_signal = pyqtSignal(dict)
    edit_signal = pyqtSignal(dict)
    delete_signal = pyqtSignal(dict)
    copy_pass_signal = pyqtSignal(dict)

    def __init__(self, entry: dict, parent=None):
        super().__init__(parent)
        self.entry = entry
        self._hovered = False
        self._build()
        self.setFixedHeight(64)
        self.setCursor(QCursor(Qt.PointingHandCursor))

    def _build(self):
        lay = QHBoxLayout(self)
        lay.setContentsMargins(16, 0, 12, 0)
        lay.setSpacing(14)

        # avatar circle
        name = self.entry.get("name", "?")
        initials = entry_avatar(name)
        color = avatar_color(name)

        self.avatar = AvatarLabel(initials, color)
        self.avatar.setFixedSize(38, 38)
        lay.addWidget(self.avatar)

        # text
        text_col = QVBoxLayout(); text_col.setSpacing(2)
        self.name_lbl = QLabel(name)
        self.name_lbl.setStyleSheet(f"color:{C['text']};font-size:14px;font-weight:600;background:transparent;")
        sub_text = self.entry.get("username") or self.entry.get("url") or ""
        self.sub_lbl = QLabel(sub_text)
        self.sub_lbl.setStyleSheet(f"color:{C['text3']};font-size:12px;background:transparent;")
        text_col.addWidget(self.name_lbl)
        text_col.addWidget(self.sub_lbl)
        lay.addLayout(text_col, stretch=1)

        # action buttons
        self.btn_copy = QPushButton("📋")
        self.btn_copy.setObjectName("icon_btn")
        self.btn_copy.setFixedSize(28, 28)
        self.btn_copy.setStyleSheet("QPushButton#icon_btn{padding:2px 4px;}")
        self.btn_copy.setToolTip(t("tip_copy_pass"))
        self.btn_copy.clicked.connect(lambda: self.copy_pass_signal.emit(self.entry))
        self.btn_copy.hide()

        self.btn_edit = QPushButton("✏️")
        self.btn_edit.setObjectName("icon_btn")
        self.btn_edit.setFixedSize(28, 28)
        self.btn_edit.setStyleSheet("QPushButton#icon_btn{padding:2px 4px;}")
        self.btn_edit.setToolTip(t("tip_edit"))
        self.btn_edit.clicked.connect(lambda: self.edit_signal.emit(self.entry))
        self.btn_edit.hide()

        lay.addWidget(self.btn_copy)
        lay.addWidget(self.btn_edit)

        # chevron
        chev = QLabel("›")
        chev.setStyleSheet(f"color:{C['text4']};font-size:20px;background:transparent;")
        lay.addWidget(chev)

    def mousePressEvent(self, e):
        if e.button() == Qt.LeftButton:
            self.clicked_signal.emit(self.entry)
        super().mousePressEvent(e)

    def enterEvent(self, e):
        self._hovered = True
        self.btn_copy.show(); self.btn_edit.show()
        self.setStyleSheet(f"background-color:{C['bg2']};border-radius:10px;")
        super().enterEvent(e)

    def leaveEvent(self, e):
        self._hovered = False
        self.btn_copy.hide(); self.btn_edit.hide()
        self.setStyleSheet("background-color:transparent;")
        super().leaveEvent(e)

class AvatarLabel(QWidget):
    def __init__(self, text: str, color: str, parent=None):
        super().__init__(parent)
        self.text = text; self.color = color

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        # Draw circle
        bg = QColor(self.color)
        bg.setAlpha(30)
        p.setBrush(QBrush(bg)); p.setPen(Qt.NoPen)
        p.drawEllipse(0, 0, w, h)
        # Text
        p.setPen(QPen(QColor(self.color)))
        f = QFont(); f.setPointSize(max(8, w//3)); f.setBold(True)
        p.setFont(f)
        p.drawText(self.rect(), Qt.AlignCenter, self.text)

# detail panel

class DetailPanel(QWidget):
    edit_requested = pyqtSignal(dict)
    delete_requested = pyqtSignal(dict)
    copy_pass_requested = pyqtSignal(dict)
    copy_user_requested = pyqtSignal(dict)
    closed = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.entry = None
        self._pass_visible = False
        self._build()

    def _build(self):
        self.setMinimumWidth(320)
        self.setStyleSheet(f"background: {C['bg1']};")

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        # header
        header = QWidget()
        header.setFixedHeight(56)
        header.setStyleSheet(f"background: {C['bg1']};")
        hl = QHBoxLayout(header)
        hl.setContentsMargins(20, 0, 16, 0)

        close_btn = QPushButton("✕")
        close_btn.setObjectName("ghost")
        close_btn.setFixedSize(30, 30)
        close_btn.setStyleSheet(f"QPushButton{{background:transparent;border:none;color:{C['text3']};font-size:14px;}}"
                                f"QPushButton:hover{{color:{C['text']};background:{C['bg3']};border-radius:6px;}}")
        close_btn.clicked.connect(self.closed.emit)
        hl.addWidget(close_btn)
        hl.addStretch()

        self.edit_btn = QPushButton(t("btn_edit"))
        self.edit_btn.setFixedHeight(32)
        self.edit_btn.clicked.connect(lambda: self.edit_requested.emit(self.entry) if self.entry else None)
        hl.addWidget(self.edit_btn)
        lay.addWidget(header)

        # scroll area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet(f"background: {C['bg1']};")

        content = QWidget()
        content.setStyleSheet(f"background: {C['bg1']};")
        self.content_lay = QVBoxLayout(content)
        self.content_lay.setContentsMargins(24, 28, 24, 28)
        self.content_lay.setSpacing(0)
        scroll.setWidget(content)
        lay.addWidget(scroll, stretch=1)

        # bottom delete button
        bot = QWidget()
        bot.setStyleSheet(f"background: {C['bg1']};")
        bl = QHBoxLayout(bot); bl.setContentsMargins(20, 12, 20, 12)
        self.del_btn = QPushButton(t("btn_delete"))
        self.del_btn.setObjectName("danger")
        self.del_btn.setFixedHeight(34)
        self.del_btn.clicked.connect(lambda: self.delete_requested.emit(self.entry) if self.entry else None)
        bl.addStretch(); bl.addWidget(self.del_btn); bl.addStretch()
        lay.addWidget(bot)

        self.hide()

    def show_entry(self, entry: dict):
        self.entry = entry
        self._pass_visible = False

        # clear
        while self.content_lay.count():
            item = self.content_lay.takeAt(0)
            if item.widget(): item.widget().deleteLater()

        name = entry.get("name", "")
        color = avatar_color(name)

        # Avatar + name
        av_w = QWidget()
        av_l = QVBoxLayout(av_w)
        av_l.setAlignment(Qt.AlignCenter)
        av_l.setSpacing(12)
        av = AvatarLabel(entry_avatar(name), color)
        av.setFixedSize(64, 64)
        av.setStyleSheet("margin: auto;")
        av_l.addWidget(av, alignment=Qt.AlignCenter)
        n_lbl = QLabel(name)
        n_lbl.setStyleSheet(f"color:{C['text']};font-size:20px;font-weight:700;background:transparent;")
        n_lbl.setAlignment(Qt.AlignCenter)
        av_l.addWidget(n_lbl)
        url = entry.get("url", "")
        if url:
            u_lbl = QLabel(url)
            u_lbl.setStyleSheet(f"color:{C['accent']};font-size:12px;background:transparent;")
            u_lbl.setAlignment(Qt.AlignCenter)
            av_l.addWidget(u_lbl)
        self.content_lay.addWidget(av_w)
        self.content_lay.addSpacing(28)

        # Fields
        if entry.get("username"):
            self._add_field(t("username_label"), entry["username"],
                            copy_fn=lambda: self.copy_user_requested.emit(self.entry))
            self.content_lay.addSpacing(2)

        # password field with show/hide
        pw_w = self._make_pass_field(entry.get("password", ""))
        self.content_lay.addWidget(pw_w)

        if entry.get("notes"):
            self.content_lay.addSpacing(2)
            self._add_field(t("notes_label"), entry["notes"])

        self.content_lay.addSpacing(20)

        # metadata
        meta = QLabel(f"{t('created_label')}: {entry.get('created_at','')[:10]}  ·  "
                      f"{t('updated_label')}: {entry.get('updated_at','')[:10]}")
        meta.setStyleSheet(f"color:{C['text4']};font-size:11px;background:transparent;")
        meta.setWordWrap(True)
        self.content_lay.addWidget(meta)
        self.content_lay.addStretch()

        self.show()

    def _add_field(self, label: str, value: str, copy_fn=None):
        w = QWidget()
        w.setStyleSheet(f"background:{C['bg2']};border-radius:10px;")
        vl = QVBoxLayout(w); vl.setContentsMargins(14, 12, 14, 12); vl.setSpacing(4)

        lbl = QLabel(label)
        lbl.setStyleSheet(f"color:{C['text4']};font-size:10px;font-weight:700;letter-spacing:0.8px;background:transparent;")
        vl.addWidget(lbl)

        row = QHBoxLayout(); row.setSpacing(8)
        val = QLabel(value)
        val.setStyleSheet(f"color:{C['text']};font-size:14px;background:transparent;")
        val.setWordWrap(True)
        row.addWidget(val, stretch=1)

        if copy_fn:
            cb = QPushButton("📄")
            cb.setObjectName("icon_btn")
            cb.setFixedSize(28, 28)
            cb.clicked.connect(copy_fn)
            row.addWidget(cb)
        vl.addLayout(row)
        self.content_lay.addWidget(w)

    def _make_pass_field(self, password: str) -> QWidget:
        w = QWidget()
        w.setStyleSheet(f"background:{C['bg2']};border-radius:10px;")
        vl = QVBoxLayout(w); vl.setContentsMargins(14, 12, 14, 12); vl.setSpacing(4)

        lbl = QLabel(t("password_label"))
        lbl.setStyleSheet(f"color:{C['text4']};font-size:10px;font-weight:700;letter-spacing:0.8px;background:transparent;")
        vl.addWidget(lbl)

        row = QHBoxLayout(); row.setSpacing(8)
        self.pass_lbl = QLabel("••••••••••••")
        self.pass_lbl.setStyleSheet(f"color:{C['text']};font-size:15px;letter-spacing:3px;background:transparent;")
        row.addWidget(self.pass_lbl, stretch=1)

        # eye button
        eye = QPushButton("👁")
        eye.setObjectName("icon_btn")
        eye.setFixedSize(28, 28)
        eye.setStyleSheet("QPushButton#icon_btn{padding:2px;}")
        eye.setCheckable(True)
        def toggle_pass(checked):
            self._pass_visible = checked
            self.pass_lbl.setText(password if checked else "••••••••••••")
            self.pass_lbl.setStyleSheet(
                f"color:{C['text']};font-size:{'14px' if checked else '15px'};"
                f"letter-spacing:{'0px' if checked else '3px'};background:transparent;")
        eye.toggled.connect(toggle_pass)
        row.addWidget(eye)

        # Copy button
        cb = QPushButton("📋")
        cb.setObjectName("icon_btn")
        cb.setFixedSize(28, 28)
        cb.setStyleSheet("QPushButton#icon_btn{padding:2px;}")
        cb.clicked.connect(lambda: self.copy_pass_requested.emit(self.entry))
        row.addWidget(cb)

        vl.addLayout(row)
        return w

# entery dialog
class EntryDialog(QDialog):
    def __init__(self, parent=None, entry=None):
        super().__init__(parent)
        self.entry = entry
        self.setWindowFlags(Qt.Dialog | Qt.FramelessWindowHint)
        self.setFixedWidth(480)
        self.setFixedHeight(580)
        self.setModal(True)
        self._build()
        if entry: self._load(entry)
        QTimer.singleShot(0, self._apply_mask)

    def _apply_mask(self):
        from PyQt5.QtCore import QRectF as QRF
        rect = QRF(0, 0, self.width(), self.height())
        radius = 20
        path = QPainterPath()
        path.addRoundedRect(rect, radius, radius)
        self.setMask(QRegion(path.toFillPolygon().toPolygon()))

    def _build(self):
        self.setStyleSheet(QSS + f"""
            QDialog {{
                background: {C['bg1']};
                border-radius: 16px;
            }}
        """)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(32, 28, 32, 28)
        lay.setSpacing(16)

        # title
        self.title = QLabel(t("dlg_edit_entry") if self.entry else t("dlg_add_entry"))
        self.title.setStyleSheet(f"color:{C['text']};font-size:18px;font-weight:700;background:transparent;")
        lay.addWidget(self.title)

        def add_field(label, widget):
            lbl = QLabel(label)
            lbl.setStyleSheet(f"color:{C['text3']};font-size:11px;font-weight:600;background:transparent;")
            lay.addWidget(lbl)
            lay.addWidget(widget)

        self.nm = QLineEdit(); self.nm.setPlaceholderText(t("ph_name")); self.nm.setFixedHeight(40)
        self.ur = QLineEdit(); self.ur.setPlaceholderText(t("ph_url")); self.ur.setFixedHeight(40)
        self.us = QLineEdit(); self.us.setPlaceholderText(t("ph_username")); self.us.setFixedHeight(40)

        add_field(t("lbl_name"), self.nm)
        add_field(t("lbl_url"), self.ur)
        add_field(t("lbl_username"), self.us)

        # password row
        pw_lbl = QLabel(t("lbl_password"))
        pw_lbl.setStyleSheet(f"color:{C['text3']};font-size:11px;font-weight:600;background:transparent;")
        lay.addWidget(pw_lbl)

        pw_row = QHBoxLayout(); pw_row.setSpacing(8)
        self.pw = QLineEdit(); self.pw.setPlaceholderText(t("ph_password"))
        self.pw.setEchoMode(QLineEdit.Password); self.pw.setFixedHeight(40)

        eye = QPushButton("🔍"); eye.setObjectName("icon_btn"); eye.setFixedSize(40, 40)
        eye.setCheckable(True)
        eye.toggled.connect(lambda c: self.pw.setEchoMode(QLineEdit.Normal if c else QLineEdit.Password))

        gen = QPushButton(t("btn_generate_short")); gen.setObjectName("secondary")
        gen.setFixedHeight(40); gen.clicked.connect(self._gen)

        pw_row.addWidget(self.pw); pw_row.addWidget(eye); pw_row.addWidget(gen)
        lay.addLayout(pw_row)

        # strength bar
        self.sbar = StrengthBar()
        lay.addWidget(self.sbar)
        self.pw.textChanged.connect(self._strength)

        # notes
        notes_lbl = QLabel(t("lbl_notes"))
        notes_lbl.setStyleSheet(f"color:{C['text3']};font-size:11px;font-weight:600;background:transparent;")
        lay.addWidget(notes_lbl)
        self.nt = QTextEdit(); self.nt.setPlaceholderText(t("ph_notes"))
        self.nt.setFixedHeight(72)
        lay.addWidget(self.nt)

        # buttons
        br = QHBoxLayout(); br.setSpacing(10)
        cancel = QPushButton(t("btn_cancel")); cancel.setObjectName("secondary")
        cancel.setFixedHeight(40); cancel.clicked.connect(self.reject)
        save_btn = QPushButton(t("btn_save")); save_btn.setFixedHeight(40)
        save_btn.clicked.connect(self._save)
        save_btn.setDefault(True)
        br.addWidget(cancel); br.addWidget(save_btn)
        lay.addLayout(br)

    def _strength(self, text):
        sc, lb = password_strength(text)
        self.sbar.set_strength(sc, lb)

    def _gen(self):
        dlg = GeneratorDialog(self)
        if dlg.exec_() == QDialog.Accepted: self.pw.setText(dlg.result)

    def _load(self, e):
        self.nm.setText(e.get("name", ""))
        self.ur.setText(e.get("url", ""))
        self.us.setText(e.get("username", ""))
        self.pw.setText(e.get("password", ""))
        self.nt.setPlainText(e.get("notes", ""))

    def _save(self):
        base_style = f"""
            QLineEdit {{
                background: {C['bg2']};
                color: {C['text']};
                border: 1px solid {C['border']};
                border-radius: 8px;
                padding: 9px 13px;
                font-size: 14px;
                selection-background-color: {C['accent']};
            }}
            QLineEdit:focus {{
                border-color: {C['accent']};
                background-color: {C['bg2']};
                outline: none;
            }}
            QLineEdit::placeholder {{ color: {C['text4']}; }}
        """
        has_error = False
        if not self.nm.text().strip():
            self.nm.setStyleSheet(base_style + f"border-color:{C['red']};")
            has_error = True
        else:
            self.nm.setStyleSheet(base_style)
        if not self.pw.text():
            self.pw.setStyleSheet(base_style + f"border-color:{C['red']};")
            has_error = True
        else:
            self.pw.setStyleSheet(base_style)
        if has_error:
            return
        self.accept()

    def data(self) -> dict:
        return {
            "name": self.nm.text().strip(),
            "url": self.ur.text().strip(),
            "username": self.us.text().strip(),
            "password": self.pw.text(),
            "notes": self.nt.toPlainText().strip()
        }

# generation dialog

class GeneratorDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.result = ""
        self.setWindowFlags(Qt.Dialog | Qt.FramelessWindowHint)
        self.setFixedWidth(440)
        self.setFixedHeight(520)
        self.setModal(True)
        self._copied = False
        self._build()
        self._gen()
        self._apply_mask()

    def _apply_mask(self):
        from PyQt5.QtCore import QRectF as QRF
        rect = QRF(0, 0, self.width(), self.height())
        radius = 20
        path = QPainterPath()
        path.addRoundedRect(rect, radius, radius)
        self.setMask(QRegion(path.toFillPolygon().toPolygon()))

    def _build(self):
        self.setStyleSheet(QSS + f"""
            QDialog {{
                background: {C['bg1']};
                border-radius: 16px;
            }}
        """)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(28, 28, 28, 28)
        lay.setSpacing(16)

        title = QLabel(t("gen_title"))
        title.setStyleSheet(f"color:{C['text']};font-size:18px;font-weight:700;background:transparent;")
        lay.addWidget(title)

        # Password display
        pw_row = QHBoxLayout(); pw_row.setSpacing(10)
        self.rl = QLineEdit(); self.rl.setReadOnly(True); self.rl.setFixedHeight(50)
        self.rl.setStyleSheet(f"""
            QLineEdit {{
                font-family: 'SF Mono', 'Fira Code', 'Courier New', monospace;
                font-size: 16px; font-weight: 600;
                color: {C['accent']};
                background: {C['bg3']};
                border: 1px solid {C['border']};
                border-radius: 10px;
                padding: 0 14px;
                letter-spacing: 1px;
            }}
        """)
        refresh = QPushButton("⬅"); refresh.setObjectName("secondary")
        refresh.setFixedSize(50, 50)
        refresh.setStyleSheet(f"QPushButton{{background:{C['bg3']};border:1px solid {C['border']};border-radius:10px;color:{C['text']};font-size:18px;}}"
                              f"QPushButton:hover{{background:{C['bg4']};color:{C['accent']};border-color:{C['accent']};}} QPushButton:pressed{{background:{C['bg2']};}}")
        refresh.clicked.connect(self._gen)
        pw_row.addWidget(self.rl); pw_row.addWidget(refresh)
        lay.addLayout(pw_row)

        # Strength & entropy
        self.sbar = StrengthBar(); lay.addWidget(self.sbar)
        self.slbl = QLabel("")
        self.slbl.setStyleSheet(f"color:{C['text3']};font-size:11px;background:transparent;")
        lay.addWidget(self.slbl)

        # Length
        len_row = QHBoxLayout()
        ll = QLabel(t("lbl_length"))
        ll.setStyleSheet(f"color:{C['text3']};font-size:12px;background:transparent;")
        self.sp = QSpinBox(); self.sp.setRange(8, 128); self.sp.setValue(20); self.sp.setFixedWidth(64)
        len_row.addWidget(ll); len_row.addStretch(); len_row.addWidget(self.sp)
        lay.addLayout(len_row)

        self.sl = QSlider(Qt.Horizontal); self.sl.setRange(8, 128); self.sl.setValue(20)
        self.sl.valueChanged.connect(self.sp.setValue)
        self.sp.valueChanged.connect(self.sl.setValue)
        self.sl.valueChanged.connect(self._gen)
        lay.addWidget(self.sl)

        self._copy_lbl = QLabel("")
        self._copy_lbl.setStyleSheet(f"color:{C['green']};font-size:12px;background:transparent;")
        lay.addWidget(self._copy_lbl)

        # Checkboxes
        chk_row = QHBoxLayout(); chk_row.setSpacing(8)
        self.cu = QCheckBox(t("chk_upper")); self.cl = QCheckBox(t("chk_lower"))
        self.cd = QCheckBox(t("chk_digits")); self.cs = QCheckBox(t("chk_symbols"))
        for c in [self.cu, self.cl, self.cd, self.cs]:
            c.setChecked(True); c.stateChanged.connect(self._gen); chk_row.addWidget(c)
        lay.addLayout(chk_row)

        br = QHBoxLayout(); br.setSpacing(10)
        cancel = QPushButton(t("btn_cancel")); cancel.setObjectName("secondary")
        cancel.setFixedHeight(40); cancel.clicked.connect(self.reject)
        use_btn = QPushButton(t("btn_use_password")); use_btn.setFixedHeight(40)
        use_btn.clicked.connect(self._copy_and_close)
        use_btn.setDefault(True)
        br.addWidget(cancel); br.addWidget(use_btn)
        lay.addLayout(br)

    def _gen(self):
        import math
        length = self.sp.value()
        pwd = generate_password(
            length,
            use_upper=self.cu.isChecked(),
            use_lower=self.cl.isChecked(),
            use_digits=self.cd.isChecked(),
            use_symbols=self.cs.isChecked(),
        )
        self.result = pwd
        self.rl.setText(pwd)
        sc, lb = password_strength(pwd)
        self.sbar.set_strength(sc, lb)
        alphabet_size = 0
        if self.cu.isChecked(): alphabet_size += 26
        if self.cl.isChecked(): alphabet_size += 26
        if self.cd.isChecked(): alphabet_size += 10
        if self.cs.isChecked(): alphabet_size += len(SYMBOLS)
        if alphabet_size < 1: alphabet_size = 52
        entropy = length * math.log2(alphabet_size)
        self.slbl.setText(t("gen_entropy", n=length, e=entropy))
        self._copy_lbl.setText("")
        self._copied = False

    def _copy_password(self):
        copy_to_clipboard(self.result)
        self._copy_lbl.setText(t("status_copy_pass"))
        self._copied = True

    def _copy_and_close(self):
        copy_to_clipboard(self.result)
        self._copy_lbl.setText(t("status_copy_pass"))
        self.accept()

# backup

class BackupDialog(QDialog):
    def __init__(self, db, key, parent=None):
        super().__init__(parent); self.db = db; self.key = key
        self.setWindowFlags(Qt.Dialog | Qt.FramelessWindowHint)
        self.setFixedSize(420, 320)
        self.setModal(True)
        self._build()
        self._apply_mask()

    def _apply_mask(self):
        from PyQt5.QtCore import QRectF as QRF
        rect = QRF(0, 0, self.width(), self.height())
        radius = 20
        path = QPainterPath()
        path.addRoundedRect(rect, radius, radius)
        self.setMask(QRegion(path.toFillPolygon().toPolygon()))

    def _build(self):
        self.setStyleSheet(QSS + f"""
            QDialog {{
                background: {C['bg1']};
                border-radius: 16px;
            }}
        """)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        header = QWidget()
        header.setFixedHeight(56)
        header.setStyleSheet(f"background: {C['bg1']}; border-top-left-radius: 16px; border-top-right-radius: 16px;")
        hl = QHBoxLayout(header)
        hl.setContentsMargins(20, 0, 16, 0)

        close_btn = QPushButton("✕")
        close_btn.setObjectName("ghost")
        close_btn.setFixedSize(30, 30)
        close_btn.setStyleSheet(f"QPushButton{{background:transparent;border:none;color:{C['text3']};font-size:14px;}}"
                               f"QPushButton:hover{{color:{C['text']};background:{C['bg3']};border-radius:6px;}}")
        close_btn.clicked.connect(self.reject)
        hl.addWidget(close_btn)
        hl.addStretch()

        t_ = QLabel(t("backup_title"))
        t_.setStyleSheet(f"color:{C['text']};font-size:16px;font-weight:700;background:transparent;")
        hl.addWidget(t_)
        hl.addStretch()
        lay.addWidget(header)

        content = QWidget()
        content.setStyleSheet(f"background: {C['bg1']};")
        cl = QVBoxLayout(content)
        cl.setContentsMargins(24, 20, 24, 20)
        cl.setSpacing(16)

        icon_w = QWidget()
        icon_l = QVBoxLayout(icon_w)
        icon_l.setAlignment(Qt.AlignCenter)
        icon = QLabel("📦")
        icon.setStyleSheet("font-size: 48px; background: transparent;")
        icon_l.addWidget(icon)
        cl.addWidget(icon_w)

        desc = QLabel(t("backup_desc"))
        desc.setWordWrap(True)
        desc.setAlignment(Qt.AlignCenter)
        desc.setStyleSheet(f"color:{C['text3']};font-size:13px;background:transparent;line-height:1.5;")
        cl.addWidget(desc)

        self.msg = QLabel("")
        self.msg.setWordWrap(True)
        self.msg.setAlignment(Qt.AlignCenter)
        self.msg.setStyleSheet(f"color:{C['green']};font-size:12px;background:transparent;")
        self.msg.hide()
        cl.addWidget(self.msg)
        cl.addStretch()

        br = QHBoxLayout()
        br.setSpacing(12)
        cl_b = QPushButton(t("btn_cancel"))
        cl_b.setObjectName("secondary")
        cl_b.setFixedHeight(40)
        cl_b.clicked.connect(self.accept)
        bk = QPushButton(t("backup_btn"))
        bk.setFixedHeight(40)
        bk.clicked.connect(self._do)
        br.addWidget(cl_b)
        br.addWidget(bk)
        cl.addLayout(br)

        lay.addWidget(content)

    def _do(self):
        default = f"r-pass_{datetime.now().strftime('%Y%m%d_%H%M%S')}.r-pass"
        path, _ = QFileDialog.getSaveFileName(self, t("backup_save_dialog"),
                                              str(Path.home() / default), t("backup_filter"))
        if not path: return
        if not path.endswith(".r-pass"): path += ".r-pass"
        try:
            self.db.export_backup(self.key, path)
            self.msg.setText(t("backup_success", path=path))
            self.msg.setStyleSheet(f"color:{C['green']};font-size:12px;background:transparent;")
            self.msg.show()
        except Exception as e:
            self.msg.setText(t("backup_error", err=str(e)))
            self.msg.setStyleSheet(f"color:{C['red']};font-size:12px;background:transparent;")
            self.msg.show()

# restore

class RestoreDialog(QDialog):
    restored = pyqtSignal(int)

    def __init__(self, db, key, parent=None):
        super().__init__(parent); self.db = db; self.key = key
        self.setWindowFlags(Qt.Dialog | Qt.FramelessWindowHint)
        self.setFixedSize(440, 420)
        self.setModal(True)
        self._build()
        self._apply_mask()

    def _apply_mask(self):
        from PyQt5.QtCore import QRectF as QRF
        rect = QRF(0, 0, self.width(), self.height())
        radius = 20
        path = QPainterPath()
        path.addRoundedRect(rect, radius, radius)
        self.setMask(QRegion(path.toFillPolygon().toPolygon()))

    def _build(self):
        self.setStyleSheet(QSS + f"""
            QDialog {{
                background: {C['bg1']};
                border-radius: 16px;
            }}
        """)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        header = QWidget()
        header.setFixedHeight(56)
        header.setStyleSheet(f"background: {C['bg1']}; border-top-left-radius: 16px; border-top-right-radius: 16px;")
        hl = QHBoxLayout(header)
        hl.setContentsMargins(20, 0, 16, 0)

        close_btn = QPushButton("✕")
        close_btn.setObjectName("ghost")
        close_btn.setFixedSize(30, 30)
        close_btn.setStyleSheet(f"QPushButton{{background:transparent;border:none;color:{C['text3']};font-size:14px;}}"
                               f"QPushButton:hover{{color:{C['text']};background:{C['bg3']};border-radius:6px;}}")
        close_btn.clicked.connect(self.reject)
        hl.addWidget(close_btn)
        hl.addStretch()

        t_ = QLabel(t("restore_title"))
        t_.setStyleSheet(f"color:{C['text']};font-size:16px;font-weight:700;background:transparent;")
        hl.addWidget(t_)
        hl.addStretch()
        lay.addWidget(header)

        content = QWidget()
        content.setStyleSheet(f"background: {C['bg1']};")
        cl = QVBoxLayout(content)
        cl.setContentsMargins(24, 20, 24, 20)
        cl.setSpacing(14)

        icon_w = QWidget()
        icon_l = QVBoxLayout(icon_w)
        icon_l.setAlignment(Qt.AlignCenter)
        icon = QLabel("📥")
        icon.setStyleSheet("font-size: 40px; background: transparent;")
        icon_l.addWidget(icon)
        cl.addWidget(icon_w)

        desc = QLabel(t("restore_desc"))
        desc.setWordWrap(True)
        desc.setAlignment(Qt.AlignCenter)
        desc.setStyleSheet(f"color:{C['text3']};font-size:12px;background:transparent;line-height:1.5;")
        cl.addWidget(desc)

        fr = QHBoxLayout(); fr.setSpacing(8)
        self.fp = QLineEdit(); self.fp.setReadOnly(True); self.fp.setPlaceholderText(".r-pass")
        self.fp.setFixedHeight(38)
        bb = QPushButton(t("restore_browse")); bb.setObjectName("secondary")
        bb.setFixedHeight(38); bb.clicked.connect(self._browse)
        fr.addWidget(self.fp); fr.addWidget(bb); cl.addLayout(fr)

        ml = QLabel(t("restore_mode_label"))
        ml.setStyleSheet(f"color:{C['text3']};font-size:11px;font-weight:600;background:transparent;")
        cl.addWidget(ml)

        self.rb_merge = QRadioButton(t("restore_mode_merge"))
        self.rb_replace = QRadioButton(t("restore_mode_replace"))
        self.rb_merge.setChecked(True)
        for rb in [self.rb_merge, self.rb_replace]:
            rb.setStyleSheet(f"QRadioButton{{color:{C['text3']};padding:4px 0;}}"
                            f"QRadioButton::indicator{{width:16px;height:16px;border-radius:8px;border:1.5px solid {C['border2']};background:{C['bg2']};}}"
                            f"QRadioButton::indicator:checked{{background:{C['accent']};border-color:{C['accent']};}}")
            cl.addWidget(rb)

        self.errl = QLabel("")
        self.errl.setWordWrap(True)
        self.errl.setAlignment(Qt.AlignCenter)
        self.errl.setStyleSheet(f"color:{C['red']};font-size:11px;background:transparent;")
        self.errl.hide()
        cl.addWidget(self.errl)

        self.okl = QLabel("")
        self.okl.setWordWrap(True)
        self.okl.setAlignment(Qt.AlignCenter)
        self.okl.setStyleSheet(f"color:{C['green']};font-size:11px;background:transparent;")
        self.okl.hide()
        cl.addWidget(self.okl)

        cl.addStretch()

        br = QHBoxLayout(); br.setSpacing(12)
        cl_btn = QPushButton(t("btn_cancel")); cl_btn.setObjectName("secondary"); cl_btn.setFixedHeight(40); cl_btn.clicked.connect(self.reject)
        self.rb_btn = QPushButton(t("restore_btn")); self.rb_btn.setFixedHeight(40); self.rb_btn.clicked.connect(self._do)
        br.addWidget(cl_btn); br.addWidget(self.rb_btn); cl.addLayout(br)

        lay.addWidget(content)

    def _browse(self):
        p, _ = QFileDialog.getOpenFileName(self, t("restore_open_dialog"), str(Path.home()), t("restore_filter"))
        if p: self.fp.setText(p)

    def _do(self):
        self.errl.hide(); self.okl.hide()
        path = self.fp.text().strip()
        if not path or not os.path.isfile(path):
            self.errl.setText(t("restore_err_no_file")); self.errl.show(); return
        self.rb_btn.setEnabled(False)
        try:
            n = self.db.import_backup(self.key, path, replace=self.rb_replace.isChecked())
            self.okl.setText(t("restore_success", n=n)); self.okl.show()
            self.restored.emit(n)
        except ValueError as e:
            msg = t("restore_err_bad_file") if str(e) == "invalid_file" else t("restore_err_wrong_pass")
            self.errl.setText(msg); self.errl.show()
        except Exception as e:
            self.errl.setText(str(e)); self.errl.show()
        finally:
            self.rb_btn.setEnabled(True)

# main Window

class MainWindow(QMainWindow):
    CLIP_MS  = 30_000
    LOCK_MS  = 900_000   # 15 min auto-lock

    def __init__(self, db, key):
        super().__init__()
        self.db = db; self.key = key
        self._entries = []
        self._selected_entry = None

        self._clip_timer = QTimer(self); self._clip_timer.setSingleShot(True)
        self._clip_timer.timeout.connect(self._clear_clipboard)
        self._lock_timer = QTimer(self); self._lock_timer.setSingleShot(True)
        self._lock_timer.timeout.connect(self._auto_lock)
        self._lock_timer.start(self.LOCK_MS)

        self._build()
        self._reload()
        self.setWindowTitle("r-pass")
        self.resize(1100, 680)
        self._center()

    def _center(self):
        g = QApplication.primaryScreen().geometry(); s = self.frameGeometry()
        self.move((g.width() - s.width()) // 2, (g.height() - s.height()) // 2)

    def _reset_lock_timer(self):
        self._lock_timer.start(self.LOCK_MS)

    # build ui

    def _build(self):
        self.setStyleSheet(QSS)
        cw = QWidget(); self.setCentralWidget(cw)
        root = QHBoxLayout(cw)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_sidebar())

        # main area

        self._main_splitter = QSplitter(Qt.Horizontal)
        self._main_splitter.setHandleWidth(0)
        self._main_splitter.setStyleSheet("QSplitter::handle{background:transparent;}")

        self._main_area = self._build_main_area()
        self._detail_panel = DetailPanel()
        self._detail_panel.edit_requested.connect(self._edit)
        self._detail_panel.delete_requested.connect(self._del)
        self._detail_panel.copy_pass_requested.connect(self._cpp)
        self._detail_panel.copy_user_requested.connect(self._cpu)
        self._detail_panel.closed.connect(self._detail_panel.hide)

        self._main_splitter.addWidget(self._main_area)
        self._main_splitter.addWidget(self._detail_panel)
        self._main_splitter.setSizes([700, 340])
        self._main_splitter.setCollapsible(1, True)
        self._main_splitter.setCollapsible(0, False)

        root.addWidget(self._main_splitter, stretch=1)

        # status bar
        self.sb = QStatusBar(); self.setStatusBar(self.sb)
        self.sb.setFixedHeight(26)
        self._clip_lbl = QLabel()
        self._clip_lbl.setStyleSheet(f"color:{C['accent']};font-size:11px;")
        self.sb.addPermanentWidget(self._clip_lbl)

    def _build_sidebar(self) -> QWidget:
        sb = QWidget()
        sb.setFixedWidth(220)
        sb.setStyleSheet(f"background:{C['bg1']};")

        lay = QVBoxLayout(sb)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        # Logo area
        logo_w = QWidget()
        logo_w.setFixedHeight(56)
        logo_w.setStyleSheet(f"background:{C['bg1']};")

        logo_l = QHBoxLayout(logo_w)
        logo_l.setContentsMargins(20, 0, 20, 0)
        logo_l.setAlignment(Qt.AlignVCenter)

        name_lbl = QLabel("r-pass")
        name_lbl.setStyleSheet(f"""
            color: {C['text']};
            font-size: 18px;
            font-weight: 700;
            background: transparent;
            letter-spacing: 0.5px;
        """)

        logo_l.addWidget(name_lbl)
        lay.addWidget(logo_w)

        lay.addSpacing(8)

        def nav_btn(text, fn, danger=False):
            b = QPushButton(text); b.setObjectName("ghost")
            b.setFixedHeight(38)
            color = C['red'] if danger else C['text2']
            hover_bg = "rgba(255,69,58,0.1)" if danger else C['bg3']
            b.setStyleSheet(f"""
                QPushButton {{
                    background: transparent;
                    color: {color};
                    border: none;
                    text-align: left;
                    padding: 0 20px;
                    font-size: 13px;
                    font-weight: 500;
                    border-radius: 0;
                }}
                QPushButton:hover {{
                    background: {hover_bg};
                    color: {'#FF6B6B' if danger else C['text']};
                }}
            """)
            b.clicked.connect(fn)
            return b

        self._btn_all = nav_btn(t("all_entries"), self._filter_all)
        lay.addWidget(self._btn_all)

        sep = QFrame(); sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet(f"background:{C['border']};max-height:1px;border:none;margin:8px 0;")
        lay.addWidget(sep)

        self._btn_backup = nav_btn("↓  " + t("backup"), self._open_backup)
        self._btn_restore = nav_btn("↑  " + t("restore"), self._open_restore)
        lay.addWidget(self._btn_backup)
        lay.addWidget(self._btn_restore)

        sep2 = QFrame(); sep2.setFrameShape(QFrame.HLine)
        sep2.setStyleSheet(f"background:{C['border']};max-height:1px;border:none;margin:8px 0;")
        lay.addWidget(sep2)

        self._btn_lang = nav_btn("🌐 " + t("language"), self._open_lang)
        lay.addWidget(self._btn_lang)

        lay.addStretch()

        # Crypto info
        ci = QLabel("AES-256-GCM · Argon2id")
        ci.setStyleSheet(f"color:{C['text4']};font-size:10px;background:transparent;padding:0 20px 8px;")
        lay.addWidget(ci)

        self._btn_lock = nav_btn("🔒  " + t("lock"), self._lock, danger=False)
        lay.addWidget(self._btn_lock)
        return sb

    def _build_main_area(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet(f"background:{C['bg']};")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        # Toolbar
        toolbar = QWidget()
        toolbar.setFixedHeight(56)
        toolbar.setStyleSheet(f"background:{C['bg']};")
        tl = QHBoxLayout(toolbar)
        tl.setContentsMargins(24, 0, 20, 0)
        tl.setSpacing(12)

        self._title = QLabel(t("entries_header"))
        self._title.setStyleSheet(f"color:{C['text']};font-size:18px;font-weight:700;background:transparent;")
        tl.addWidget(self._title)
        tl.addStretch()

        # search panel
        search_container = QWidget()
        search_container.setFixedSize(260, 36)

        self.search_input = QLineEdit(search_container)
        self.search_input.setPlaceholderText(t("search_placeholder"))
        self.search_input.setGeometry(0, 0, 260, 36)
        self.search_input.setStyleSheet(f"""
            QLineEdit {{
                background: {C['bg2']};
                border: 1px solid {C['border']};
                border-radius: 18px;
                color: {C['text']};
                font-size: 13px;
                padding: 0 14px;
            }}
            QLineEdit:focus {{
                border-color: {C['accent']};
            }}
            QLineEdit::placeholder {{ color: {C['text4']}; }}
        """)
        self.search_input.textChanged.connect(self._search)
        tl.addWidget(search_container)
        tl.addStretch()

        # new button
        self._new_btn = QPushButton("➕  " + t("btn_new_entry"))
        self._new_btn.setFixedHeight(36)
        self._new_btn.setStyleSheet(f"""
            QPushButton {{
                background: {C['accent']};
                color: white;
                border-radius: 10px;
                font-size: 13px;
                font-weight: 600;
                border: none;
                padding: 0 16px;
            }}
            QPushButton:hover {{ background: {C['accent2']}; }}
        """)
        self._new_btn.clicked.connect(self._add)
        tl.addWidget(self._new_btn)

        # generate
        self._gen_btn = QPushButton("🔑")
        self._gen_btn.setObjectName("secondary")
        self._gen_btn.setFixedSize(44, 36)
        self._gen_btn.setStyleSheet(f"""
            QPushButton {{
                background: {C['bg3']};
                border: 1px solid {C['border']};
                border-radius: 8px;
                font-size: 18px;
                padding: 0 4px;
            }}
            QPushButton:hover {{
                background: {C['bg4']};
                border-color: {C['border2']};
            }}
        """)
        self._gen_btn.setToolTip(t("btn_generate"))
        self._gen_btn.clicked.connect(lambda: GeneratorDialog(self).exec_())
        tl.addWidget(self._gen_btn)

        lay.addWidget(toolbar)

        sep = QFrame(); sep.setFixedHeight(1)
        sep.setStyleSheet(f"background:{C['border']};")
        lay.addWidget(sep)

        # Count label
        self._count_lbl = QLabel("")
        self._count_lbl.setStyleSheet(f"color:{C['text4']};font-size:11px;background:{C['bg']};padding:6px 24px 4px;")
        lay.addWidget(self._count_lbl)

        # scroll area for cards
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet(f"background:{C['bg']};")

        self._list_widget = QWidget()
        self._list_widget.setStyleSheet(f"background:{C['bg']};")
        self._list_lay = QVBoxLayout(self._list_widget)
        self._list_lay.setContentsMargins(16, 8, 16, 16)
        self._list_lay.setSpacing(2)
        self._list_lay.addStretch()

        scroll.setWidget(self._list_widget)
        lay.addWidget(scroll, stretch=1)

        QShortcut(QKeySequence("Ctrl+F"), self, self.search_input.setFocus)
        QShortcut(QKeySequence("Ctrl+N"), self, self._add)

        return w

    # data management

    def _reload(self, q=""):
        self._entries = self.db.list_entries(self.key, q)
        self._render()

    def _render(self):
        while self._list_lay.count() > 1:
            item = self._list_lay.takeAt(0)
            if item.widget(): item.widget().deleteLater()

        if not self._entries:
            empty = QWidget()
            empty_l = QVBoxLayout(empty)
            empty_l.setAlignment(Qt.AlignCenter)
            empty_l.setSpacing(12)
            ei = QLabel("🔐")
            ei.setStyleSheet(f"font-size:48px;background:transparent;")
            ei.setAlignment(Qt.AlignCenter)
            en = QLabel(t("no_entries"))
            en.setStyleSheet(f"color:{C['text3']};font-size:16px;font-weight:600;background:transparent;")
            en.setAlignment(Qt.AlignCenter)
            es = QLabel(t("no_entries_sub"))
            es.setStyleSheet(f"color:{C['text4']};font-size:13px;background:transparent;")
            es.setAlignment(Qt.AlignCenter)
            empty_l.addWidget(ei); empty_l.addWidget(en); empty_l.addWidget(es)
            self._list_lay.insertWidget(0, empty)
            self._count_lbl.setText("")
            return

        for i, entry in enumerate(self._entries):
            card = EntryCardWidget(entry)
            card.clicked_signal.connect(self._show_detail)
            card.edit_signal.connect(self._edit)
            card.delete_signal.connect(self._del)
            card.copy_pass_signal.connect(self._cpp)
            self._list_lay.insertWidget(i, card)

        n = len(self._entries)
        self._count_lbl.setText(t("n_entries", n=n))

    def _show_detail(self, entry: dict):
        self._reset_lock_timer()
        self._selected_entry = entry
        self._detail_panel.show_entry(entry)
        sizes = self._main_splitter.sizes()
        if sizes[1] < 100:
            self._main_splitter.setSizes([700, 340])

    # slots
    def _search(self, q):
        self._reset_lock_timer()
        self._reload(q.strip())

    def _filter_all(self):
        self.search_input.clear()
        self._reload()

    def _add(self):
        self._reset_lock_timer()
        dlg = EntryDialog(self)
        if dlg.exec_() == QDialog.Accepted:
            d = dlg.data()
            self.db.add_entry(self.key, d["name"], d["url"], d["username"], d["password"], d["notes"])
            self._reload(self.search_input.text().strip())
            self.sb.showMessage(t("status_added", name=d["name"]), 3000)

    def _edit(self, entry: dict):
        self._reset_lock_timer()
        dlg = EntryDialog(self, entry=entry)
        if dlg.exec_() == QDialog.Accepted:
            d = dlg.data()
            self.db.update_entry(self.key, entry["id"], d["name"], d["url"],
                                 d["username"], d["password"], d["notes"])
            self._reload(self.search_input.text().strip())
            self.sb.showMessage(t("status_updated", name=d["name"]), 3000)
            if self._detail_panel.isVisible():
                updated = next((e for e in self._entries if e["id"] == entry["id"]), None)
                if updated: self._detail_panel.show_entry(updated)

    def _del(self, entry: dict):
        self._reset_lock_timer()
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle(t("confirm_delete_title"))
        msg_box.setText(t("confirm_delete_msg", name=entry["name"]))
        msg_box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        msg_box.setDefaultButton(QMessageBox.No)
        msg_box.setStyleSheet(QSS + f"QMessageBox{{background:{C['bg1']};}} QLabel{{color:{C['text2']};font-size:14px;}}")
        if msg_box.exec_() == QMessageBox.Yes:
            self.db.delete_entry(entry["id"])
            if self._detail_panel.isVisible() and self._detail_panel.entry and \
               self._detail_panel.entry["id"] == entry["id"]:
                self._detail_panel.hide()
            self._reload(self.search_input.text().strip())
            self.sb.showMessage(t("status_deleted", name=entry["name"]), 3000)

    def _cpu(self, entry: dict):
        self._reset_lock_timer()
        u = entry.get("username", "")
        if u:
            copy_to_clipboard(u)
            self.sb.showMessage(t("status_copy_user"), 2000)

    def _cpp(self, entry: dict):
        self._reset_lock_timer()
        pw = entry.get("password", "")
        if pw:
            copy_to_clipboard(pw)
            self._clip_timer.start(self.CLIP_MS)
            self._clip_lbl.setText("⏱ 30s")
            self.sb.showMessage(t("status_copy_pass"), 3000)

    def _clear_clipboard(self):
        clear_clipboard()
        self._clip_lbl.setText("")
        self.sb.showMessage(t("status_clip_cleared"), 2000)

    def _open_backup(self):
        self._reset_lock_timer()
        BackupDialog(self.db, self.key, self).exec_()

    def _open_restore(self):
        self._reset_lock_timer()
        dlg = RestoreDialog(self.db, self.key, self)
        dlg.restored.connect(lambda n: (
            self._reload(self.search_input.text().strip()),
            self.sb.showMessage(t("restore_success", n=n), 4000)
        ))
        dlg.exec_()

    def _open_lang(self):
        self._reset_lock_timer()
        dlg = LanguageDialog(self)
        if dlg.exec_() == QDialog.Accepted:
            self._btn_all.setText(t("all_entries"))
            self._btn_backup.setText("↓  " + t("backup"))
            self._btn_restore.setText("↑  " + t("restore"))
            self._btn_lang.setText("🌐 " + t("language"))
            self._btn_lock.setText("🔒  " + t("lock"))
            self._title.setText(t("entries_header"))
            self._new_btn.setText("➕  " + t("btn_new_entry"))
            self.search_input.setPlaceholderText(t("search_placeholder"))
            self._gen_btn.setToolTip(t("btn_generate"))
            if hasattr(self, '_detail_panel') and self._detail_panel:
                self._detail_panel.edit_btn.setText(t("btn_edit"))
                self._detail_panel.del_btn.setText(t("btn_delete"))
            self._reload(self.search_input.text().strip())
            self.sb.showMessage(t("lang_restart_note"), 3000)

    def _auto_lock(self):
        self.sb.showMessage(t("status_auto_locked"), 3000)
        self._relock()

    def _lock(self):
        self._relock()

    def _relock(self, force_setup=False):
        self.key = None
        self._entries.clear()
        self.hide()
        restart_unlock(self.db, force_setup=force_setup)

# helpers

def copy_to_clipboard(text: str):
    if CLIP_AVAILABLE:
        try: pyperclip.copy(text); return
        except Exception: pass
    QApplication.clipboard().setText(text)

def clear_clipboard():
    if CLIP_AVAILABLE:
        try: pyperclip.copy(""); return
        except Exception: pass
    QApplication.clipboard().clear()

# bootstartup

def restart_unlock(db, force_setup=False):
    if force_setup:
        mode = "setup"
    else:
        mode = "setup" if not db.is_initialized() else "unlock"

    dlg = LoginScreen(db, mode=mode)
    if dlg.exec_() == QDialog.Accepted and dlg.key:
        win = MainWindow(db, dlg.key)
        win.show()
        QApplication.instance()._win = win
    else:
        QApplication.instance().quit()


def main():
    cfg = load_settings(); set_lang(cfg.get("lang", "en"))

    if hasattr(Qt, "AA_EnableHighDpiScaling"):
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    if hasattr(Qt, "AA_UseHighDpiPixmaps"):
        QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setApplicationName("r-pass")
    app.setOrganizationName("r-pass")
    app.setApplicationVersion("2.0.0")

    db = Database()
    mode = "setup" if not db.is_initialized() else "unlock"
    dlg = LoginScreen(db, mode=mode)

    if dlg.exec_() != QDialog.Accepted or dlg.key is None:
        sys.exit(0)

    win = MainWindow(db, dlg.key)
    app._win = win
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
