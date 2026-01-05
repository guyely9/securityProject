import hashlib
import secrets

import bcrypt
from argon2 import PasswordHasher
from argon2.low_level import Type

from config import HASH_MODE, PROTECTION_FLAGS, PEPPER, BCRYPT_COST

_argon2 = PasswordHasher(time_cost=1, memory_cost= 65536, parallelism= 1,type=Type.ID)

def add_pepper(password):
    if PROTECTION_FLAGS["pepper"]:
        return password + PEPPER
    return password


def make_password(password):
    pwd = add_pepper(password)

    if HASH_MODE == "sha256_salt":
        salt = secrets.token_hex(16)
        digest = hashlib.sha256((salt + pwd).encode("utf-8")).hexdigest()
        return digest, salt, "sha256_salt"

    if HASH_MODE == "bcrypt":
        pw_hash = bcrypt.hashpw(
            pwd.encode("utf-8"),
            bcrypt.gensalt(rounds=BCRYPT_COST)
        ).decode("utf-8")
        return pw_hash, None, "bcrypt"

    if HASH_MODE == "argon2id":
        pw_hash = _argon2.hash(pwd)
        return pw_hash, None, "argon2id"

    raise ValueError(f"Unknown HASH_MODE: {HASH_MODE}")


def check_password(password, stored_hash, salt, hash_mode):
    pwd = add_pepper(password)
    if hash_mode == "sha256_salt":
        if salt is None:
            return False
        digest = hashlib.sha256((salt + pwd).encode("utf-8")).hexdigest()
        return digest == stored_hash

    if hash_mode == "bcrypt":
        return bcrypt.checkpw(pwd.encode("utf-8"), stored_hash.encode("utf-8"))

    if hash_mode == "argon2id":
        try:
            return _argon2.verify(stored_hash, pwd)
        except Exception:
            return False

    return False
