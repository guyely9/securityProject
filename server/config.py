import os
GUY_ID = 212979629
HALEL_ID = 331702712
GROUP_SEED = GUY_ID^HALEL_ID

# "sha256_salt" | "bcrypt" | "argon2id"
HASH_MODE = "bcrypt"

BCRYPT_COST = 12
DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")
PEPPER = 'dacd127151ab278dd0e9d7981c0a474201b400bcb2a156010d004b0190ddb5f3'
RATE_LIMIT_TRY = 10
RATE_LIMIT_TIME = 60
LOCKOUT_TRY = 5
LOCKOUT_TIME = 300
PROTECTION_FLAGS = {
    "pepper": False,
    "totp": False,
    "rate_limit": False,
    "lockout": True,
    "captcha": False
}