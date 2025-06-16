import streamlit as st
import joblib
import pandas as pd
from urllib.parse import urlparse
import ipaddress
import matplotlib.pyplot as plt
import re

# Load model
model = joblib.load("phising_model.pkl")

# Kolom fitur yang digunakan oleh model
FEATURE_COLUMNS = [
    'Unnamed: 0', 'NumDots', 'UrlLength', 'NumDash', 'AtSymbol',
    'IpAddress', 'HttpsInHostname', 'PathLevel', 'PathLength',
    'NumNumericChars', 'SuspiciousKeyword'
]

# Kata-kata mencurigakan yang sering muncul di URL phishing
SUSPICIOUS_WORDS = ['login', 'verify', 'secure', 'account', 'update', 'bank', 'confirm', 'click']

# Fungsi kategorisasi untuk ditampilkan
def categorize_feature(name, value):
    if name == "NumDots":
        return "Rendah" if value <= 0 else "Sedang" if value <= 2 else "Tinggi"
    elif name == "UrlLength":
        return "Pendek" if value <= 50 else "Sedang" if value <= 100 else "Panjang"
    elif name == "NumDash":
        return "Rendah" if value == 0 else "Sedang" if value <= 3 else "Tinggi"
    return "N/A"

# Fungsi ekstraksi fitur dari URL
def extract_features_from_url(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ''
    path = parsed.path or ''

    def is_ip_address(domain):
        try:
            ipaddress.ip_address(domain)
            return 1
        except:
            return 0

    def count_digits(s):
        return sum(c.isdigit() for c in s)

    def path_level(path):
        return path.count('/')

    def contains_suspicious_words(url):
        return int(any(word in url.lower() for word in SUSPICIOUS_WORDS))

    num_dots = url.count('.')
    url_length = len(url)
    num_dash = url.count('-')
    at_symbol = url.count('@')
    ip_address = is_ip_address(hostname)
    https_in_hostname = int('https' in hostname.lower())
    path_lvl = path_level(path)
    path_length = len(path)
    num_digits = count_digits(url)
    suspicious_keyword = contains_suspicious_words(url)

    features = [
        0, num_dots, url_length, num_dash, at_symbol, ip_address,
        https_in_hostname, path_lvl, path_length, num_digits, suspicious_keyword
    ]

    categories = {
        "NumDots": categorize_feature("NumDots", num_dots),
        "UrlLength": categorize_feature("UrlLength", url_length),
        "NumDash": categorize_feature("NumDash", num_dash),
        "SuspiciousKeyword": "Ya" if suspicious_keyword else "Tidak"
    }

    raw_values = {
        'NumDots': num_dots,
        'UrlLength': url_length,
        'NumDash': num_dash,
        'AtSymbol': at_symbol,
        'IpAddress': ip_address,
        'HttpsInHostname': https_in_hostname,
        'PathLevel': path_lvl,
        'PathLength': path_length,
        'NumNumericChars': num_digits,
        'SuspiciousKeyword': suspicious_keyword
    }

    return features, categories, raw_values

# Streamlit UI
st.set_page_config(page_title="Deteksi Phishing URL", page_icon="🔒")
st.title("🔍 Deteksi Phishing URL Menggunakan Naive Bayes")

url_input = st.text_input("Masukkan URL yang ingin diperiksa:")

if st.button("Deteksi"):
    if url_input:
        try:
            features, categories, raw_values = extract_features_from_url(url_input)
            input_df = pd.DataFrame([features], columns=FEATURE_COLUMNS)

            prediction = model.predict(input_df)[0]
            probability = model.predict_proba(input_df)[0][1]

            label = "⚠️ Phishing" if prediction == 1 else "✅ Aman"
            st.markdown(f"### Hasil Deteksi: {label}")
            st.write(f"**Probabilitas Phishing:** {probability:.2f}")

            # Tampilkan kategori fitur
            st.subheader("📊 Kategori Fitur Utama")
            st.markdown(f"- **Jumlah Titik (NumDots)**: {categories['NumDots']} ({raw_values['NumDots']})")
            st.markdown(f"- **Panjang URL (UrlLength)**: {categories['UrlLength']} ({raw_values['UrlLength']})")
            st.markdown(f"- **Jumlah Tanda Minus (NumDash)**: {categories['NumDash']} ({raw_values['NumDash']})")
            st.markdown(f"- **Kata Mencurigakan**: {categories['SuspiciousKeyword']}")

        except Exception as e:
            st.error(f"Terjadi kesalahan saat memproses URL: {e}")
    else:
        st.warning("Masukkan URL terlebih dahulu.")