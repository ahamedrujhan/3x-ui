import json
import base64
import os
import time
import hashlib
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [cert-watcher] %(message)s'
)

ACME_PATH = '/app/acme.json'
CERTS_DIR = '/app/certs'
CHECK_INTERVAL = 3600  # check every hour


def get_file_hash(path):
    try:
        with open(path, 'rb') as f:
            return hashlib.md5(f.read()).hexdigest()
    except Exception:
        return None


def extract_certs(acme_path, certs_dir):
    try:
        with open(acme_path) as f:
            data = json.load(f)

        for resolver, resolver_data in data.items():
            certs = resolver_data.get('Certificates', [])
            if not certs:
                logging.warning(f'No certificates found in resolver: {resolver}')
                continue

            for c in certs:
                domain = c['domain']['main']
                domain_dir = os.path.join(certs_dir, domain)
                os.makedirs(domain_dir, exist_ok=True)

                cert_path = os.path.join(domain_dir, 'fullchain.pem')
                key_path = os.path.join(domain_dir, 'privkey.pem')

                cert_data = base64.b64decode(c['certificate']).decode()
                key_data = base64.b64decode(c['key']).decode()

                with open(cert_path, 'w') as f:
                    f.write(cert_data)

                with open(key_path, 'w') as f:
                    f.write(key_data)

                logging.info(f'Extracted cert for: {domain} → {domain_dir}')

    except Exception as e:
        logging.error(f'Failed to extract certs: {e}')


def main():
    logging.info('Starting cert watcher...')
    last_hash = None

    # Extract immediately on start
    extract_certs(ACME_PATH, CERTS_DIR)
    last_hash = get_file_hash(ACME_PATH)

    while True:
        time.sleep(CHECK_INTERVAL)
        current_hash = get_file_hash(ACME_PATH)

        if current_hash != last_hash:
            logging.info('acme.json changed — extracting new certs...')
            extract_certs(ACME_PATH, CERTS_DIR)
            last_hash = current_hash
        else:
            logging.info('acme.json unchanged — no action needed')


if __name__ == '__main__':
    main()