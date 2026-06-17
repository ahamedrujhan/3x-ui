import json
import base64
import os
import time
import hashlib
import logging
import sqlite3
import urllib.request

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [cert-watcher] %(message)s'
)

ACME_PATH = '/app/acme.json'
CERTS_DIR = '/app/certs'
DB_PATH = '/app/db/x-ui.db'
CHECK_INTERVAL = 3600


def get_file_hash(path):
    try:
        with open(path, 'rb') as f:
            return hashlib.md5(f.read()).hexdigest()
    except Exception:
        return None


def extract_certs(acme_path, certs_dir):
    extracted = []
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

                with open(cert_path, 'w') as f:
                    f.write(base64.b64decode(c['certificate']).decode())

                with open(key_path, 'w') as f:
                    f.write(base64.b64decode(c['key']).decode())

                logging.info(f'Extracted cert for: {domain} → {domain_dir}')
                extracted.append({
                    'domain': domain,
                    'cert': f'/root/cert/{domain}/fullchain.pem',
                    'key': f'/root/cert/{domain}/privkey.pem'
                })

    except Exception as e:
        logging.error(f'Failed to extract certs: {e}')

    return extracted


def update_xray_inbounds(db_path, extracted):
    if not extracted:
        return False

    updated_any = False
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT id, remark, stream_settings FROM inbounds")
        rows = cursor.fetchall()

        for row_id, remark, stream_json in rows:
            try:
                stream = json.loads(stream_json)
                tls = stream.get('tlsSettings', {})
                certs = tls.get('certificates', [])

                if not certs:
                    logging.info(f'Inbound {row_id} ({remark}) has no TLS — skipping')
                    continue

                domain_info = extracted[0]
                cert_file = domain_info['cert']
                key_file = domain_info['key']

                updated = False
                for cert in certs:
                    if cert.get('certificateFile') != cert_file or cert.get('keyFile') != key_file:
                        cert['certificateFile'] = cert_file
                        cert['keyFile'] = key_file
                        updated = True

                if updated:
                    stream['tlsSettings']['certificates'] = certs
                    cursor.execute(
                        "UPDATE inbounds SET stream_settings = ? WHERE id = ?",
                        (json.dumps(stream), row_id)
                    )
                    logging.info(f'Updated inbound {row_id} ({remark}) → {cert_file}')
                    updated_any = True
                else:
                    logging.info(f'Inbound {row_id} ({remark}) already correct — skipping')

            except Exception as e:
                logging.error(f'Failed to update inbound {row_id}: {e}')

        conn.commit()
        conn.close()
        logging.info('Database updated successfully')

    except Exception as e:
        logging.error(f'Failed to connect to database: {e}')

    return updated_any


def reload_xray():
    # Just touch a file — x-ui watches for changes and reloads Xray
    try:
        req = urllib.request.Request(
            'http://3xui_app:2053/xui/API/inbounds',
            headers={'Accept': 'application/json'}
        )
        urllib.request.urlopen(req, timeout=5)
        logging.info('Xray reload triggered via API')
    except Exception as e:
        logging.warning(f'Could not trigger reload via API: {e}')
        logging.warning('Please restart 3xui manually once: docker restart 3xui_app')


def main():
    logging.info('Starting cert watcher...')

    # Wait for acme.json and db to exist
    for path in [ACME_PATH, DB_PATH]:
        while not os.path.exists(path):
            logging.info(f'Waiting for {path}...')
            time.sleep(5)

    # Extra wait for 3xui to fully initialize
    time.sleep(10)

    last_hash = None

    # Run immediately on start
    extracted = extract_certs(ACME_PATH, CERTS_DIR)
    updated = update_xray_inbounds(DB_PATH, extracted)
    if updated:
        logging.info('Cert paths updated in DB — restart 3xui_app once to apply')
    last_hash = get_file_hash(ACME_PATH)

    while True:
        time.sleep(CHECK_INTERVAL)
        current_hash = get_file_hash(ACME_PATH)

        if current_hash != last_hash:
            logging.info('acme.json changed — extracting new certs...')
            extracted = extract_certs(ACME_PATH, CERTS_DIR)
            updated = update_xray_inbounds(DB_PATH, extracted)
            if updated:
                reload_xray()
            last_hash = current_hash
        else:
            logging.info('acme.json unchanged — no action needed')


if __name__ == '__main__':
    main()