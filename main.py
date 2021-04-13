import time
import hashlib
import click
import re

@click.command()
@click.option('--type', default=None, help='Type of hash')
@click.option('--hash', default=None, help='MD5 hash to crack')
@click.option('--hashfile', default=None, help='File of hashes to crack')
@click.option('--wordlist', default=None, help='Path to wordlist')
def main(type, hash, hashfile, wordlist):
    counter = 1
    type = type
    md5_hash = hash
    pwdfile = wordlist
    try:
        pwdfile = open(pwdfile, 'r')
    except:
        print("\n File not found...")
        quit()
    if hashfile:
        for password in pwdfile:
            hashed = hashlib.md5(password.strip().encode('utf-8')).hexdigest()
            for item in hashfile:
                split_string = re.split(':', item)
                start = time.time()
                print(f'Trying password {counter}: {password.strip()}')
                counter += 1
                end = time.time()
                t_time = end - start
                if split_string == hashed.upper() or  split_string == hashed.lower():
                    print(f'[+] Password found: {password}')
                    print(f'Total runtime was -- {t_time} seconds')
                    time.sleep(10)
                    exit(0)

    for password in pwdfile:
        if type == 'md5':
            filemd5 = hashlib.md5(password.strip().encode('utf-8')).hexdigest()
            start = time.time()
            print(f'Trying password {counter}: {password.strip()}')
            counter += 1
            end = time.time()
            t_time = end - start
            if md5_hash == filemd5.upper() or md5_hash == filemd5.lower():
                print(f'[+] Password found: {password}')
                print(f'Total runtime was -- {t_time} seconds')
                time.sleep(10)
                exit(0)
            else:
                print(f'[-] Incorrect password tested: {password}')
        elif type == 'sha-1':
            filesha1 = hashlib.sha1(password.strip().encode('utf-8')).hexdigest()
            start = time.time()
            print(f'Trying password {counter}: {password.strip()}')
            counter += 1
            end = time.time()
            t_time = end - start
            if md5_hash == filesha1.upper() or md5_hash == filesha1.lower():
                print(f'[+] Password found: {password}')
                print(f'Total runtime was -- {t_time} seconds')
                time.sleep(10)
                exit(0)
            else:
                print(f'[-] Incorrect password tested: {password}')


if __name__ == "__main__":
    main()
