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

alice_secret = "PQE6UTKFIXGLCYQPK52THBDS2LLHKOGM"#pyotp.random_base32()
print(alice_secret)

users = {
    "alice": {
        "password_hash": hash_password(
            "Cyber123!"
        ),
        "totp_secret": alice_secret
    }
}
totp = pyotp.TOTP(
    users["alice"]["totp_secret"]
)

uri = totp.provisioning_uri(
    name="alice",
    issuer_name="FSCT8561-Lab3"
)

print(uri)