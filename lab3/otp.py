import hashlib
import pyotp

def hash_password(password):
    return hashlib.sha256(
        password.encode()
    ).hexdigest()

def verify_password(password, stored_hash):
    if password == stored_hash:
        return True
    else:
        return False

def verify_otp(secret, otp):
    totp = pyotp.TOTP(secret)
    return totp.verify(otp)

alice_secret = pyotp.random_base32()

users = {
    "alice": {
        "password_hash": hash_password(
            "Cyber123!"
        ),
        "totp_secret": alice_secret
    }
}
totp = pyotp.TOTP(alice_secret)


print(
    "Alice's TOTP secret:",
    users["alice"]["totp_secret"]
)