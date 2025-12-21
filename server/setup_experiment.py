import requests
import json

BASE_URL = "http://127.0.0.1:5000"

GUY_ID = 212979629
HALEL_ID = 331702712
GROUP_SEED = str(GUY_ID ^ HALEL_ID)

users_to_create = [
  # easy passwords
  *[{"username": f"weak_user_{i}", "password": p} for i, p in enumerate(["123456", "password", "12345", "12345678", "qwerty", "1234", "111111", "1234567", "password123", GROUP_SEED])],
  # medium passwords
  *[{"username": f"med_user_{i}", "password": f"Pass{i*123}!"} for i in range(10)],
  # hard passwords
  *[{"username": f"strong_user_{i}", "password": f"Complex#Long#Pwd#{i}#2025!"} for i in range(10)]
]

def register_users():
    print(f"--- Starting registration for {len(users_to_create)} users ---")
    for user in users_to_create:
        response = requests.post(f"{BASE_URL}/register", json=user)
        if response.status_code == 201:
            print(f"Successfully registered: {user['username']}")
        else:
            print(f"Failed to register {user['username']}: {response.json().get('error')}")

if __name__ == "__main__":
    register_users()
