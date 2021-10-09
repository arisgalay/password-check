import requests
import hashlib
import sys


def request_api_data(query):
    url = 'https://api.pwnedpasswords.com/range/' + str(query)
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError
    return res


def pw_leak_counts(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return False


def pwned_api_check(pw):
    sha1_pw = hashlib.sha1(pw.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1_pw[:5], sha1_pw[5:]
    response = request_api_data(first5_char)
    return pw_leak_counts(response, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} have been pwned! {count} times.')
        else:
            print(f'{password} is not been pwned, All good!')
    return 'Done!!'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
