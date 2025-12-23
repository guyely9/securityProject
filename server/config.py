import os
GUY_ID = 212979629
HALEL_ID = 331702712
GROUP_SEED = GUY_ID^HALEL_ID

# "sha256_salt" | "bcrypt" | "argon2id"
HASH_MODE = "bcrypt"

BCRYPT_COST = 12
DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")

ENABLE_PEPPER = False
PEPPER = 'dacd127151ab278dd0e9d7981c0a474201b400bcb2a156010d004b0190ddb5f3'