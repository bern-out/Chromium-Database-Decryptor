#!/usr/bin/env python3
import json
from Crypto.Cipher import AES
import sqlite3
import argparse

APP_BOUND_KEY: bytes 

def decrypt_password(blob: bytes, key: bytes) -> str:
    if blob == 0:
        return ""
    if not (blob.startswith(b'v10') or blob.startswith(b'v20')):
        print(f"Skipped entry: not v10/v20 or too small.")
        return ""

    iv = blob[3:15]
    ciphertext = blob[15:-16]
    tag = blob[-16:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    decrypted = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted.decode('utf-8', errors='replace')


def decrypt_cookie(blob: bytes, key: bytes):
    if blob is None or len(blob) < 19:
        return None

    if blob.startswith(b'v20'):
        iv = blob[3:15]
        ciphertext = blob[15:-16]
        tag = blob[-16:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        decrypted = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted[32:].decode('utf-8', errors='replace')  # strip 32-byte App-Bound prefix

    elif blob.startswith(b'v10'):
        iv = blob[3:15]
        ciphertext = blob[15:-16]
        tag = blob[-16:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        decrypted = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted.decode('utf-8', errors='replace')  # sem strip no v10

    else:
        print("Skipped entry: formato desconhecido.")
        return None



def get_passwords(cursor: sqlite3.Cursor, output_file: None|str):
    query = """
    SELECT origin_url, action_url, username_value, password_value FROM logins
    """
    cursor.execute(query)
    rows = cursor.fetchall()

    if output_file:
        export_passwords_json_file(output_file, rows)
        return

    print_passwords(rows)


def get_cookies(cursor: sqlite3.Cursor, output_file: str|None):
    query = """
    SELECT
        name,
        encrypted_value,
        host_key,
        path,
        expires_utc,
        is_secure,
        is_httponly,
        samesite
    FROM cookies
    """
    rows = cursor.execute(query)
    
    if output_file:
        export_cookies_json_file(output_file, rows)
        return
    
    print_cookies(rows)


def build_cookie(row):
    name, enc_value, domain, path, expires, is_secure, is_httponly, samesite = row

    value = decrypt_cookie(enc_value, APP_BOUND_KEY)
    cookie = {
        "name": name,
        "domain": domain,
        "value": value,
        "path": path,
        "secure": bool(is_secure),
        "httpOnly": bool(is_httponly),
        "sameSite": map_same_site(samesite),
        "session": expires == 0,
        "storeId": None
    }

    if expires:
        cookie["expirationDate"] = chromium_time_to_unix(expires)

    return cookie


def print_passwords(rows):
    passwords = []

    for row in rows:
        origin_url, action_url, email, password = row
        decrypted_pass = decrypt_password(password, APP_BOUND_KEY)

        url = origin_url or action_url
        credentials = {
            'url': url,
            'email': email,
            'password': decrypted_pass
        }

        passwords.append(credentials)

    print(passwords)



def map_same_site(value: int):
    return {
        -1: "unspecified",
        0: "no_restriction",
        1: "lax",
        3: "strict"
    }.get(value)


def chromium_time_to_unix(timestamp: int):
    if timestamp == 0:
        return None
    return int(timestamp / 1_000_000 - 11644473600)


def print_cookies(rows: sqlite3.Cursor):
    cookies = []

    for row in rows:
        cookie = build_cookie(row)
        cookies.append(cookie)

    print(cookies)


def export_passwords_json_file(file: str, rows):
    passwords = []

    for row in rows:
        origin_url, action_url, username_value, password_value = row

        password = decrypt_password(password_value, APP_BOUND_KEY)
        passwords.append({
            "url": origin_url or action_url,
            "username": username_value,
            "password": password
        })

    with open(file, "w", encoding="utf-8") as f:
        json.dump(passwords, f, indent=2)

    print(f"exported {len(passwords)} passwords to {file}")


def export_cookies_json_file(file: str, rows):
    cookies = []

    for row in rows:
        cookie = build_cookie(row)
        cookies.append(cookie)

    with open(file, "w", encoding="utf-8") as f:
        json.dump(cookies, f, indent=2)

    print(f"exported {len(cookies)} cookies to {file}")


def main():
    parser = argparse.ArgumentParser("chromium_decryptor")
    parser.add_argument("-db", "--database", help="Sqlite database file containing cookies or passwords", type=str, required=True)
    parser.add_argument("-k", "--key", help="App bound key (ex: 0f206f209795890ca9764e8d643d68a6751ec60c2d7f9598d372be1ee4eab335)", type=str, required=True)

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--cookie", help="Decrypt cookies", action="store_true")
    group.add_argument('--password', help='Decrypt passwords', action='store_true')

    parser.add_argument('-o', '--output', help="Output file", type=str, required=False)

    args = parser.parse_args()

    conn = sqlite3.connect(args.database)

    global APP_BOUND_KEY
    APP_BOUND_KEY = bytes.fromhex(args.key)

    if args.password:
        get_passwords(conn.cursor(), args.output)

    if args.cookie:
        get_cookies(conn.cursor(), args.output)

    conn.close()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        raise e
