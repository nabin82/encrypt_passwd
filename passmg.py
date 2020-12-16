# Author: Nabin Bhatta
import csv
import os
import sys
import json
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
# installed the library from cryptodome since the crypto library is out-of-date
passwordFile = "secretpassword"
# The salt gives the extra layer of protection
salt = 98
message = "Welcome to password manager!!!!"  # gives welcome message
# x is the number of attempts allowed when the password is wrong!!!
x = 3


def dictToBytes(dict):  # function to return the bytes
    return json.dumps(dict).encode('utf-8')


def bytesToDict(dict):
    return json.loads(dict.decode('utf-8'))

# reference 2


def encrypt(dict, k):

    # Define the encryption scheme here.##Encrypt the dictionary value here.

    # using AES encryption
    # here the new cipher text is made and is stored in the secretpassword file and the key is secured with the encryption
    cipher = AES.new(k, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(dict)
    file_out = open(passwordFile, "wb")
    [file_out.write(x) for x in (cipher.nonce, tag, ciphertext)]
    file_out.close()


def decrypt(k):
    file_in = open(passwordFile, "rb")
    nonce, tag, ciphertext = [file_in.read(x) for x in (16, 16, -1)]

    cipher = AES.new(k, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    return data

    # with open(passwordFile, 'rb') as infile:
# ----------------------------------------------------------------------------------
    # Decrypt the session key with the private RSA key


def Main():

    # print("\n")
    mpw = input("Enter Master Password: ")

    k = PBKDF2(mpw, salt, dkLen=32)  # derive key from password

    # check for password in secret_password file
    if not os.path.isfile(passwordFile):
        # create new passwords file
        print("No password database, creating....")
        newDict = dictToBytes({"": ""})
        encrypt(newDict, k)

    # check for proper input
    if len(sys.argv) != 2:
        print("usage: python passmg.py <website_name Eg. google.com>")
        return
    else:

        # decrypt passwords file to dictionary
        try:
            print("Loading database...")
            # the password is decripted incase the database does not have the password
            pws = decrypt(k)
            pws = bytesToDict(pws)

        except Exception as e:  # incase the password is inncorrect
            # for x in range(2, 0, -1):
            global x
            x = x-1
            print("The password is incorrect. You have " +
                  str(x) + " attempts remaining.")

            if x != 0:  # consition when there are x number of attempts.
                Main()
            else:
                print("Sorry you ran out of attempts.")
            return

        # print value for  website or add new value
        entry = sys.argv[1]
        if entry in pws:
            print("entry   : " + str(entry))
            print("password: " + str(pws[entry]))
        else:
            print("No entry for " + str(entry) + ", creating new...")
            newPass = input("New entry - enter password for "+entry+": ")
            pws[entry] = newPass
            encrypt(dictToBytes(pws), k)
            print("The password is securely stored in secretpassword file!!!")


# displays main
if __name__ == '__main__':
    print(str(message))
    Main()
