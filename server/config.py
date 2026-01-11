GROUP_SEED = 527740437
HASH_MODE = "bcrypt"
BCRYPT_COST = 12
PEPPER = "SuperSecretPepper123!"
DB_PATH = "users.db"
ADMIN_KEY = "super_admin_key"
CAPTCHA_FAIL = 3
CAPTCHA_TIME = 60
LOCKOUT_TRY = 3
LOCKOUT_TIME = 300
RATE_LIMIT_TRY = 5
RATE_REFILL = 0.1
RATE_HARD_LOCK = True

PROTECTION_FLAGS = {
    "pepper": False,
    "totp": False,
    "rate_limit": False,
    "lockout": False,
    "captcha": False
}
