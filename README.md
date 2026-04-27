# Chromium Password & Cookie Decryptor

A Python tool to decrypt saved passwords and cookies from Chromium based browsers **App-Bound Key**.

--- 

## 🔧 Features

* Decrypts **Login Data** passwords (`v20` formats)
* Decrypts **Cookies** database entries
* Uses **AES-GCM decryption**
* Outputs to:

  * Console (readable format)
  * JSON (for analysis or import)

---

## ⚙️ Requirements

* Python 3.8+
* Dependencies:

  ```bash
  pip install -r requirements.txt
  ```

---

## 📂 Supported Databases

This tool works with Chromium SQLite databases such as:

* `Login Data` → stored passwords
* `Cookies` → browser cookies

You must supply:

* The database file
* The **App-Bound Key** (hex format)

---

## 🚀 Usage

### 🔑 Decrypt passwords (print to console)

```bash
python chromium_decryptor.py \
  -db "Login Data" \
  -k YOUR_APP_BOUND_KEY \
  --password
```

---

### 📤 Export passwords to JSON

```bash
python chromium_decryptor.py \
  -db "Login Data" \
  -k YOUR_APP_BOUND_KEY \
  --password \
  -o passwords.json
```

---

### 🍪 Decrypt cookies (print to console)

```bash
python chromium_decryptor.py \
  -db "Cookies" \
  -k YOUR_APP_BOUND_KEY \
  --cookie
```

---

### 📤 Export cookies to JSON

```bash
python chromium_decryptor.py \
  -db "Cookies" \
  -k YOUR_APP_BOUND_KEY \
  --cookie \
  -o cookies.json
```

---

## 🔑 App-Bound Key

The key must be provided as a **hex string**, for example:

```
0f206f209795890ca9764e8d643d68a6751ec60c2d7f9598d372be1ee4eab335
```

---

## 🔐 Legal & Ethical Use

This tool is intended for:

* Personal data recovery
* Security research
* Forensics and auditing

**Do NOT use this tool on systems or data you do not own or have explicit permission to access.**

---

## ✨ Example Output
```
{'url': 'https://www.google.com', 'email': 'example@email.com', 'password': 'password123'}
------------------------------
```

### Cookie
```
----------------------------------------
{'name': 'name', 'domain': '.site.com', 'value': 'cookie_value', 'path': '/', 'secure': True, 'httpOnly': True, 'sameSite': None, 'expires': 1808587468}
----------------------------------------
```

