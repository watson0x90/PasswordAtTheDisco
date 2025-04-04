from utils.file_utils import decode_hex

# Process domain data
def process_domain(domain, cracked_file, uncracked_file):
    cracked_accounts = []
    with open(cracked_file, 'r', encoding='utf-8') as f:
        for line in f:
            parts = line.strip().split(':')
            if len(parts) == 3:
                username, hash_, password = parts
                password = decode_hex(password)
                cracked_accounts.append({'username': username, 'hash': hash_, 'password': password, 'domain': domain})

    uncracked_accounts = []
    with open(uncracked_file, 'r', encoding='utf-8') as f:
        for line in f:
            parts = line.strip().split(':')
            if len(parts) == 2:
                username, hash_ = parts
                uncracked_accounts.append({'username': username, 'hash': hash_, 'password': None, 'domain': domain})

    return cracked_accounts, uncracked_accounts