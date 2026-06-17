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
ACME_CHECK_INTERVAL = 3600  # check acme.json every hour
DB_CHECK_INTERVAL = 30      # check db every 30 seconds for new inbounds


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

                # Always overwrite regardless of current value
                for cert in certs:
                    old_cert = cert.get('certificateFile', 'empty')
                    old_key = cert.get('keyFile', 'empty')
                    cert['certificateFile'] = cert_file
                    cert['keyFile'] = key_file
                    logging.info(f'Inbound {row_id} ({remark}) cert: {old_cert} → {cert_file}')
                    logging.info(f'Inbound {row_id} ({remark}) key:  {old_key} → {key_file}')

                stream['tlsSettings']['certificates'] = certs
                cursor.execute(
                    "UPDATE inbounds SET stream_settings = ? WHERE id = ?",
                    (json.dumps(stream), row_id)
                )
                updated_any = True

            except Exception as e:
                logging.error(f'Failed to update inbound {row_id}: {e}')

        conn.commit()
        conn.close()
        logging.info('Database updated successfully')

    except Exception as e:
        logging.error(f'Failed to connect to database: {e}')

    return updated_any


def reload_xray():
    try:
        req = urllib.request.Request(
            'http://3xui_app:2053/xui/API/inbounds',
            headers={'Accept': 'application/json'}
        )
        urllib.request.urlopen(req, timeout=5)
        logging.info('Xray reload triggered via API')
    except Exception as e:
        logging.warning(f'Could not trigger reload via API: {e}')
        logging.warning('Restart 3xui manually: docker restart 3xui_app')


def main():
    logging.info('Starting cert watcher...')

    # Wait for acme.json and db to exist
    for path in [ACME_PATH, DB_PATH]:
        while not os.path.exists(path):
            logging.info(f'Waiting for {path}...')
            time.sleep(5)

    # Wait for 3xui to fully initialize
    logging.info('Waiting for 3xui to initialize...')
    time.sleep(10)

    # Initial extraction
    extracted = extract_certs(ACME_PATH, CERTS_DIR)
    update_xray_inbounds(DB_PATH, extracted)

    last_acme_hash = get_file_hash(ACME_PATH)
    last_db_hash = get_file_hash(DB_PATH)
    last_acme_check = time.time()

    logging.info(f'Watching DB every {DB_CHECK_INTERVAL}s, acme.json every {ACME_CHECK_INTERVAL}s')

    while True:
        time.sleep(DB_CHECK_INTERVAL)

        now = time.time()
        current_db_hash = get_file_hash(DB_PATH)
        acme_changed = False

        # Check acme.json only every hour
        if now - last_acme_check >= ACME_CHECK_INTERVAL:
            current_acme_hash = get_file_hash(ACME_PATH)
            if current_acme_hash != last_acme_hash:
                logging.info('acme.json changed — extracting new certs...')
                extracted = extract_certs(ACME_PATH, CERTS_DIR)
                last_acme_hash = current_acme_hash
                acme_changed = True
            else:
                logging.info('acme.json unchanged')
            last_acme_check = now

        # Check DB every 30s — react to new/edited inbounds
        if current_db_hash != last_db_hash:
            logging.info('x-ui.db changed — new or edited inbound detected, updating cert paths...')
            updated = update_xray_inbounds(DB_PATH, extracted)
            if updated:
                reload_xray()
            last_db_hash = current_db_hash
        elif acme_changed:
            updated = update_xray_inbounds(DB_PATH, extracted)
            if updated:
                reload_xray()
        else:
            logging.debug('No changes detected')


if __name__ == '__main__':
    main()