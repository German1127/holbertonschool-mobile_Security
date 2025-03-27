# Android Cryptography Challenge: Intercepting and Decrypting Data
---
## 1. Introduction
This report details the process of intercepting, analyzing, and decrypting encrypted communication from the Android application app-release-task2.apk. The goal was to extract the hidden flag by leveraging various tools and techniques.
---
## 2. Environment Setup
To conduct the analysis, the following environment and tools were used:
**Tools Used:**
- Burp Suite
- mitmproxy
- Wireshark
- APKTool
- jadx

**Device Setup:**
- Android Emulator
- Proxy Configuration

---

## 3. Intercepting HTTP Traffic
The first step was to capture communication between the application and the remote server.
**Steps Taken:**
- Configured Burp Suite as a proxy and installed its CA certificate on the emulator.
- Ran app-release-task2.apk and monitored network requests.
- Captured encrypted responses from the server.

**Observations:**
- The application communicated via HTTPS.
- Data payloads were encrypted, requiring further cryptographic analysis.

---

## 4. APK Analysis

The next step involved analyzing the APK file to understand its cryptographic mechanisms.
**Decompilation Process:**
- Used APKTool to extract the app’s contents.
- Decompiled Java code using jadx.
- Searched for cryptographic functions in the source code.

**Key Findings:**
- AES Encryption Identified:
	- Located in a class handling network requests.
	- Used Cipher.getInstance("AES/ECB/PKCS5Padding").
	- Hardcoded key found in the source code.

- Base64 Encoding Used:
	- The encrypted data was Base64-encoded before transmission.

---


## 5. Decryption Process

With the encryption mechanism identified, the next step was to decrypt the intercepted data.
**Steps Taken:**
- Extracted the AES key from the decompiled code.
- Captured an encrypted response from the server.
- Decoded the Base64-encoded ciphertext.
- Decrypted the data using the AES key.

**Decryption Script (Python):**
```
from Crypto.Cipher import AES
import base64

def decrypt_aes(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(ciphertext))
    return decrypted.decode('utf-8')

ciphertext = "ENCRYPTED_BASE64_STRING_HERE"
key = b"HARDCODED_AES_KEY"

print(decrypt_aes(ciphertext, key))

```
---

## 6. Challenges Faced
- SSL Pinning: The app initially rejected the proxy’s CA certificate. Solution: Used Frida to bypass SSL pinning.
- Obfuscation: Some function names were obfuscated, requiring deeper analysis.

---

## 7 7. Conclusion

By intercepting and analyzing the application’s encrypted communication, we successfully decrypted the hidden flag. Weak cryptographic practices, such as hardcoded AES keys, allowed for straightforward decryption.
