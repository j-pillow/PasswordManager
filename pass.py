import sys
import base64
import os
import pandas as pd
import getpass
import cryptography as crypto
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def decryptName(siteName,saltName,password):
    kdf = PBKDF2HMAC( algorithm=hashes.SHA256(),
                      length=32,
                      salt=saltName,
                      iterations=100000,
                      backend=default_backend() 
                    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(key)
    siteName = f.decrypt(siteName)
    return siteName.decode()

# Get and test password
df = pd.read_csv("/Users/james/.pass/pass.csv")
good = False
while good == False:
    password = getpass.getpass("Password: ")
    try:
        siteDecrypt = decryptName( (df.loc[0][0]).encode('utf-8'), (df.loc[0][1]).encode('utf-8'), password)
    except crypto.fernet.InvalidToken:
        print "Incorrect password"
        continue
    good = True

# Set mode
mode = -999
if len(sys.argv) > 1:
    mode = int(sys.argv[2])
else:
    mode = int(raw_input("Would you like to encrypt/decrypt (1/0): "))


# Encrypt
if mode == 1:
    count = 0
    while True:
        site = sys.argv[1] if (count == 0 and len(sys.argv) > 1) else raw_input("Site: ")
        if (site == ""):
            break
    
        sitePassword = raw_input("Password to encrypt (leave blank for autogen): ")
        if sitePassword == "":
            sitePassword = (base64.b64encode(os.urandom(30)).decode()).encode('utf-8')
        else:
          sitePassword = (sitePassword).encode('utf-8')
        
        saltPassword = base64.b64encode(os.urandom(64))
        kdfPassword = PBKDF2HMAC( algorithm=hashes.SHA256(),
                                  length=32,
                                  salt=saltPassword,
                                  iterations=100000,
                                  backend=default_backend() 
                                )
        keyPassword = base64.urlsafe_b64encode(kdfPassword.derive(password))
        fPassword = Fernet(keyPassword)
        sitePassEncrypt = fPassword.encrypt(sitePassword)
        
        siteName = site.encode('utf-8')
        saltName = base64.b64encode(os.urandom(64))
        kdfName = PBKDF2HMAC( algorithm=hashes.SHA256(),
                              length=32,
                              salt=saltName,
                              iterations=100000,
                              backend=default_backend() 
                            )
        keyName = base64.urlsafe_b64encode(kdfName.derive(password))
        fName = Fernet(keyName)
        siteNameEncrypt = fName.encrypt(siteName)
        
        file = open("/Users/james/.pass/pass.csv", "a")
        file.write(siteNameEncrypt.decode()+","+saltName.decode()+","+sitePassEncrypt.decode()+","+saltPassword.decode() )
        file.write('\n')

        count += 1
        print

# Decrypt
if mode == 0:
    count =  0
    while True:
        site = sys.argv[1] if (count == 0 and len(sys.argv) > 1) else raw_input("Site: ")
        if (site == ""):
            break
        df = pd.read_csv("/Users/james/.pass/pass.csv")
        for i in range( 0,len(df) ):
            siteDecrypt = decryptName( (df.loc[i][0]).encode('utf-8'), (df.loc[i][1]).encode('utf-8'), password)
            if siteDecrypt == site:
                kdf = PBKDF2HMAC( algorithm=hashes.SHA256(),
                                  length=32,
                                  salt=(df.loc[i][3]).encode('utf-8'),
                                  iterations=100000,
                                  backend=default_backend()
                                )
                key = base64.urlsafe_b64encode(kdf.derive(password))
                f = Fernet(key)
                sitePass = f.decrypt((df.loc[i][2]).encode('utf-8'))
                print (sitePass.decode())
                sitePass = os.urandom(16)
                break
     
        count += 1
        print
