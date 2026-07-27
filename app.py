from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import hashlib
from secret import *
import uid_generator_pb2
import requests
from requests.adapters import HTTPAdapter
import struct
import datetime
import base64
import time
import os
import tempfile
import json
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, jsonify
from zitado_pb2 import Users

app = Flask(__name__)

# Global HTTP Session for connection pooling and TCP keep-alive
session = requests.Session()
adapter = HTTPAdapter(pool_connections=10, pool_maxsize=20)
session.mount('https://', adapter)
session.mount('http://', adapter)

TOKEN_CACHE_FILE = os.path.join(tempfile.gettempdir(), "token_cache.json")
TOKEN_CACHE = {}

def hex_to_bytes(hex_string):
    return bytes.fromhex(hex_string)

def create_protobuf(saturn_, garena):
    message = uid_generator_pb2.uid_generator()
    message.saturn_ = saturn_
    message.garena = garena
    return message.SerializeToString()

def protobuf_to_hex(protobuf_data):
    return binascii.hexlify(protobuf_data).decode()

def decode_hex(hex_string):
    byte_data = binascii.unhexlify(hex_string.replace(' ', ''))
    users = Users()
    users.ParseFromString(byte_data)
    return users

def encrypt_aes(hex_data, key, iv):
    key = key.encode()[:16]
    iv = iv.encode()[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(bytes.fromhex(hex_data), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return binascii.hexlify(encrypted_data).decode()

def apis(idd, token):
    headers = {
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)',
        'Connection': 'Keep-Alive',
        'Expect': '100-continue',
        'Authorization': f'Bearer {token}',
        'X-Unity-Version': '2018.4.11f1',
        'X-GA': 'v1 1',
        'ReleaseVersion': 'OB54',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    data = bytes.fromhex(idd)
    try:
        response = session.post('https://client.ind.freefiremobile.com/GetPlayerPersonalShow', headers=headers, data=data, timeout=5)
        return response.content.hex()
    except Exception as e:
        print(f"Error querying Free Fire API: {e}")
        return ""

def load_credentials():
    credentials = []
    base_dir = os.path.dirname(os.path.abspath(__file__))
    json_path = os.path.join(base_dir, "success-IND.json")
    txt_path = os.path.join(base_dir, "success-IND.txt")
    
    # Check success-IND.json
    if os.path.exists(json_path):
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    for item in data:
                        uid = item.get("uid")
                        password = item.get("password")
                        if uid and password:
                            credentials.append((str(uid), str(password)))
        except Exception as e:
            print(f"Error reading success-IND.json: {e}")
            
    # Check success-IND.txt
    if os.path.exists(txt_path):
        try:
            with open(txt_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
                try:
                    data = json.loads(content)
                    if isinstance(data, list):
                        for item in data:
                            uid = item.get("uid")
                            password = item.get("password")
                            if uid and password:
                                credentials.append((str(uid), str(password)))
                except json.JSONDecodeError:
                    for line in content.splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        for sep in [':', ',', '|', '\t']:
                            parts = line.split(sep)
                            if len(parts) >= 2:
                                uid = parts[0].strip()
                                password = parts[1].strip()
                                if uid.isdigit():
                                    credentials.append((uid, password))
                                    break
        except Exception as e:
            print(f"Error reading success-IND.txt: {e}")
            
    return credentials

def parse_jwt_exp(token_str):
    if not token_str or not isinstance(token_str, str):
        return None
    try:
        parts = token_str.split('.')
        if len(parts) >= 2:
            payload_b64 = parts[1]
            payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
            payload = json.loads(base64.b64decode(payload_b64).decode('utf-8'))
            return payload.get('exp')
    except Exception:
        pass
    return None

def is_token_valid(token_str):
    if not token_str or not isinstance(token_str, str):
        return False
    exp = parse_jwt_exp(token_str)
    if exp:
        # Require token to be valid for at least 5 more minutes (300s)
        return time.time() < (exp - 300)
    return True

def load_all_cached_tokens():
    global TOKEN_CACHE
    base_dir = os.path.dirname(os.path.abspath(__file__))
    paths = [
        os.path.join(base_dir, "token_cache.json"),
        TOKEN_CACHE_FILE
    ]
    for path in paths:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        if "tokens" in data and isinstance(data["tokens"], dict):
                            for uid_str, item in data["tokens"].items():
                                if isinstance(item, dict) and item.get("token"):
                                    if is_token_valid(item["token"]):
                                        TOKEN_CACHE[uid_str] = item
                        elif "token" in data:
                            tok = data["token"]
                            if is_token_valid(tok):
                                exp = parse_jwt_exp(tok) or (time.time() + 7200)
                                TOKEN_CACHE["fallback"] = {"token": tok, "exp": exp}
            except Exception as e:
                print(f"Error loading token cache from {path}: {e}")

def save_all_cached_tokens():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    paths = [
        os.path.join(base_dir, "token_cache.json"),
        TOKEN_CACHE_FILE
    ]
    data = {"tokens": TOKEN_CACHE, "updated_at": time.time()}
    for path in paths:
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except Exception as e:
            print(f"Error saving token cache to {path}: {e}")

def fetch_single_token(uid, password):
    url = f"https://jwt-beige.vercel.app/guest?uid={uid}&password={password}"
    try:
        response = session.get(url, timeout=3.5)
        if response.status_code == 200:
            res_data = response.json()
            if res_data.get("status") == "success" and res_data.get("token"):
                tok = res_data["token"]
                exp = parse_jwt_exp(tok) or (time.time() + 7200)
                return str(uid), tok, exp
    except Exception as e:
        print(f"Error fetching token for UID {uid}: {e}")
    return str(uid), None, None

def get_tokens_pool():
    credentials = load_credentials()
    fallback_token = "eyJhbGciOiJIUzI1NiIsInN2ciI6IjMiLCJ0eXAiOiJKV1QifQ.eyJhY2NvdW50X2lkIjoxMzYwNTM0ODI5NSwibmlja25hbWUiOiJZZ1JCUVZoVktEWXhhU0kvIiwibm90aV9yZWdpb24iOiJJTkQiLCJsb2NrX3JlZ2lvbiI6IklORCIsImV4dGVybmFsX2lkIjoiZDdiMzc5YmFmMmJhOWE1YTI0NDQwNGJjZDZmYWE1OTMiLCJleHRlcm5hbF90eXBlIjo0LCJwbGF0X2lkIjoxLCJjbGllbnRfdmVyc2lvbiI6IjEuMTA4LjMiLCJlbXVsYXRvcl9zY29yZSI6MTAwLCJpc19lbXVsYXRvciI6dHJ1ZSwiY291bnRyeV9jb2RlIjoiVVMiLCJleHRlcm5hbF91aWQiOjQyMzI1MDIzNzUsInJlZ19hdmF0YXIiOjEwMjAwMDAwNywic291cmNlIjowLCJsb2NrX3JlZ2lvbl90aW1lIjoxNzYwODA1OTIxLCJjbGllbnRfdHlwZSI6Miwic2lnbmF0dXJlX21kNSI6IiIsInVzaW5nX3ZlcnNpb24iOjAsInJlbGVhc2VfY2hhbm5lbCI6IiIsInJlbGVhc2VfdmVyc2lvbiI6Ik9CNTMiLCJleHAiOjE3ODA5NzExNjJ9.JEVr0hVEJo_e_CkPxfzxZpkILN15n9eYA2DvwU2_nts"

    if not TOKEN_CACHE:
        load_all_cached_tokens()

    valid_tokens = []
    missing_creds = []

    # 1. First collect all valid tokens from cache
    for uid, password in credentials:
        uid_str = str(uid)
        if uid_str in TOKEN_CACHE:
            tok_info = TOKEN_CACHE[uid_str]
            tok = tok_info.get("token")
            if is_token_valid(tok):
                valid_tokens.append(tok)
            else:
                missing_creds.append((uid, password))
        else:
            missing_creds.append((uid, password))

    # If we have valid tokens in cache, return immediately (fastest path!)
    if valid_tokens:
        return valid_tokens

    # 2. If no valid tokens in cache, fetch missing tokens in parallel
    if missing_creds:
        with ThreadPoolExecutor(max_workers=min(len(missing_creds), 5)) as executor:
            futures = [executor.submit(fetch_single_token, uid, password) for uid, password in missing_creds]
            for future in as_completed(futures):
                uid_str, tok, exp = future.result()
                if tok:
                    TOKEN_CACHE[uid_str] = {"token": tok, "exp": exp}
                    valid_tokens.append(tok)

        if valid_tokens:
            save_all_cached_tokens()

    # 3. Fallback to any token in cache or static fallback
    if not valid_tokens:
        for item in TOKEN_CACHE.values():
            if isinstance(item, dict) and item.get("token"):
                valid_tokens.append(item["token"])

    if not valid_tokens:
        valid_tokens.append(fallback_token)

    return valid_tokens

def get_token(force_refresh=False):
    pool = get_tokens_pool()
    return pool[0] if pool else None

def token(force_refresh=False):
    return get_token(force_refresh)

@app.route('/', methods=['GET'])
def home():
    return jsonify({"message": "Free Fire Player Info API is running", "usage": "/<uid>"}), 200

@app.route('/<uid>', methods=['GET'])
def main(uid):
    try:
        saturn_ = int(uid)
    except ValueError:
        return jsonify({"error": "Invalid UID format"}), 400
        
    garena = 1
    protobuf_data = create_protobuf(saturn_, garena)
    hex_data = protobuf_to_hex(protobuf_data)
    aes_key = key
    aes_iv = iv
    encrypted_hex = encrypt_aes(hex_data, aes_key, aes_iv)
    
    tokens = get_tokens_pool()
    users = None
    
    for current_token in tokens:
        infoo = apis(encrypted_hex, current_token)
        if infoo:
            try:
                decoded = decode_hex(infoo)
                if decoded and getattr(decoded, 'basicinfo', None) and len(decoded.basicinfo) > 0:
                    users = decoded
                    break
            except Exception:
                continue

    if not users or not getattr(users, 'basicinfo', None) or len(users.basicinfo) == 0:
        return jsonify({"error": "Player not found or invalid UID response"}), 404

    result = {}

    if users.basicinfo:
        result['basicinfo'] = []
        for user_info in users.basicinfo:
            bio_val = None
            if getattr(users, 'bioinfo', None) and len(users.bioinfo) > 0:
                bio_val = users.bioinfo[0].bio
            result['basicinfo'].append({
                'username': user_info.username,
                'region': user_info.region,
                'level': user_info.level,
                'Exp': user_info.Exp,
                'bio': bio_val,
                'banner': user_info.banner,
                'avatar': user_info.avatar,
                'brrankscore': user_info.brrankscore,
                'BadgeCount': user_info.BadgeCount,
                'likes': user_info.likes,
                'lastlogin': user_info.lastlogin,
                'csrankpoint': user_info.csrankpoint,
                'csrankscore': user_info.csrankscore,
                'brrankpoint': user_info.brrankpoint,
                'createat': user_info.createat,
                'OB': user_info.OB
            })

    if getattr(users, 'claninfo', None):
        result['claninfo'] = []
        for clan in users.claninfo:
            result['claninfo'].append({
                'clanid': clan.clanid,
                'clanname': clan.clanname,
                'guildlevel': clan.guildlevel,
                'livemember': clan.livemember
            })

    if getattr(users, 'clanadmin', None):
        result['clanadmin'] = []
        for admin in users.clanadmin:
            result['clanadmin'].append({
                'idadmin': admin.idadmin,
                'adminname': admin.adminname,
                'level': admin.level,
                'exp': admin.exp,
                'brpoint': admin.brpoint,
                'lastlogin': admin.lastlogin,
                'cspoint': admin.cspoint
            })

    result['Owners'] = ['@LcyiQ']
    return jsonify(result)
    
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002)
