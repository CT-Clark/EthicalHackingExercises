import hashlib
import sys

def crack_MD5_hash(hash_to_crack, salt, dictionary_file):
    file = open(dictionary_file, "r")
    for password in file:
        salted_password = (salt + password.strip("\n")).encode("UTF-8")
        if hashlib.md5(salted_password).hexdigest() == hash_to_crack:
            return password
    return None

hash_to_crack = sys.argv[0]
salt = sys.argv[1]
dict = sys.argv[2]

password = crack_MD5_hash(hash_to_crack, salt, dict)
print(password)
