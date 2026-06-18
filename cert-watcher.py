import json
import base64
import os
import time
import hashlib
import logging
import sqlite3
import socket
import threading
from collections import deque

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [cert-watcher] %(message)s'
)

ACME_PATH = '/app/acme.json'
CERTS_DIR = '/app/certs'
DB_PATH = '/app/db/x-ui.db'
DOCKER_SOCK = '/var/run/docker.sock'
CONTAINER_NAME = '3xui_app'
ACME_CHECK_INTERVAL = 3600
COOLDOWN = 15
ERROR_TRIGGERS = [
    'failed to parse certificate',
    'both file and bytes are empty',
    'failed to build TLS config',
]


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

                for cert in certs:
                    old_cert = cert.get('certificateFile') or 'empty'
                    old_key = cert.get('keyFile') or 'empty'

                    if not cert.get('certificateFile') or not cert.get('keyFile'):
                        cert['certificateFile'] = cert_file
                        cert['keyFile'] = key_file
                        logging.info(f'Inbound {row_id} ({remark}) cert: {old_cert} → {cert_file}')
                        logging.info(f'Inbound {row_id} ({remark}) key:  {old_key} → {key_file}')
                    else:
                        if not os.path.exists(cert.get('certificateFile', '')) or \
                           not os.path.exists(cert.get('keyFile', '')):
                            cert['certificateFile'] = cert_file
                            cert['keyFile'] = key_file
                            logging.info(f'Inbound {row_id} ({remark}) invalid path fixed: {old_cert} → {cert_file}')
                        else:
                            logging.info(f'Inbound {row_id} ({remark}) cert paths valid — skipping')
                            continue

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


def docker_request(method, path, body=None):
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(DOCKER_SOCK)
        sock.settimeout(30)

        headers = f'{method} {path} HTTP/1.1\r\nHost: localhost\r\n'
        if body:
            headers += f'Content-Length: {len(body)}\r\n'
        headers += '\r\n'

        sock.sendall(headers.encode())
        if body:
            sock.sendall(body.encode())

        response = b''
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        except socket.timeout:
            pass

        sock.close()
        return response.decode(errors='ignore')
    except Exception as e:
        logging.error(f'Docker request failed: {e}')
        return ''


def restart_3xui():
    logging.info('Restarting 3xui_app...')
    response = docker_request('POST', f'/containers/{CONTAINER_NAME}/restart')
    if '204' in response or response == '':
        logging.info('3xui_app restart triggered successfully')
    else:
        logging.warning(f'Unexpected restart response: {response[:100]}')


def process_queue(queue, extracted_ref):
    if not queue:
        return False
    tags = set()
    while queue:
        tags.add(queue.popleft())
    logging.info(f'Processing queued errors for tags: {tags}')
    updated = update_xray_inbounds(DB_PATH, extracted_ref['data'])
    if updated:
        restart_3xui()
    return updated


def stream_container_logs(extracted_ref, stop_event):
    logging.info('Starting log watcher for 3xui_app...')

    in_cooldown = False
    cooldown_until = 0
    queue = deque()

    while not stop_event.is_set():
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(DOCKER_SOCK)
            sock.settimeout(5)

            since = int(time.time()) - 30  # look back 30s on reconnect
            request = (
                f'GET /containers/{CONTAINER_NAME}/logs'
                f'?follow=1&stdout=1&stderr=1&tail=0&since={since} HTTP/1.1\r\n'
                f'Host: localhost\r\n\r\n'
            )
            sock.sendall(request.encode())

            header = b''
            while b'\r\n\r\n' not in header:
                header += sock.recv(1)

            status_line = header.decode(errors='ignore').split('\r\n')[0]
            is_chunked = 'chunked' in header.decode(errors='ignore').lower()
            logging.info(f'Log stream: {status_line} | chunked={is_chunked}')
            logging.info('Connected to 3xui_app log stream')

            buffer = b''
            while not stop_event.is_set():

                now = time.time()
                if in_cooldown and now >= cooldown_until:
                    in_cooldown = False
                    logging.info('Cooldown expired — scanning DB for invalid certs...')

                    # Always scan DB on cooldown expiry — catches missed errors
                    updated = update_xray_inbounds(DB_PATH, extracted_ref['data'])
                    if updated:
                        logging.info('Invalid certs found after cooldown — restarting...')
                        restart_3xui()
                        queue.clear()
                        cooldown_until = time.time() + COOLDOWN
                        in_cooldown = True
                    elif queue:
                        logging.info(f'Processing {len(queue)} queued error(s)...')
                        process_queue(queue, extracted_ref)
                        cooldown_until = time.time() + COOLDOWN
                        in_cooldown = True
                    else:
                        logging.info('No invalid certs found — all good')

                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    buffer += chunk
                except socket.timeout:
                    continue

                while b'\n' in buffer:
                    line, buffer = buffer.split(b'\n', 1)
                    log_line = line.decode(errors='ignore').strip()

                    if not log_line:
                        continue

                    try:
                        int(log_line, 16)
                        continue
                    except ValueError:
                        pass

                    logging.debug(f'3xui: {log_line}')

                    if any(trigger in log_line for trigger in ERROR_TRIGGERS):
                        tag = 'unknown'
                        for part in log_line.split():
                            if part.startswith('in-'):
                                tag = part.rstrip('>')
                                break

                        now = time.time()
                        if not in_cooldown:
                            logging.warning(f'Cert error detected [{tag}] — fixing...')
                            time.sleep(2)
                            updated = update_xray_inbounds(DB_PATH, extracted_ref['data'])
                            if updated:
                                restart_3xui()
                            cooldown_until = time.time() + COOLDOWN
                            in_cooldown = True
                        else:
                            remaining = int(cooldown_until - now)
                            if tag not in queue:
                                queue.append(tag)
                                logging.info(f'Queued [{tag}] — {remaining}s remaining, queue: {list(queue)}')
                            else:
                                logging.debug(f'[{tag}] already queued')

            sock.close()
            logging.info('Log stream disconnected — reconnecting...')

        except Exception as e:
            logging.error(f'Log stream error: {e}')
            time.sleep(5)


def main():
    logging.info('Starting cert watcher...')

    for path in [ACME_PATH, DB_PATH]:
        while not os.path.exists(path):
            logging.info(f'Waiting for {path}...')
            time.sleep(5)

    logging.info('Waiting for 3xui to initialize...')
    time.sleep(10)

    extracted = extract_certs(ACME_PATH, CERTS_DIR)
    update_xray_inbounds(DB_PATH, extracted)

    extracted_ref = {'data': extracted}
    last_acme_hash = get_file_hash(ACME_PATH)
    last_acme_check = time.time()

    stop_event = threading.Event()
    log_thread = threading.Thread(
        target=stream_container_logs,
        args=(extracted_ref, stop_event),
        daemon=True
    )
    log_thread.start()

    logging.info(f'Watching acme.json every {ACME_CHECK_INTERVAL}s')
    logging.info(f'Watching 3xui logs for cert errors (cooldown={COOLDOWN}s)')

    while True:
        time.sleep(60)
        now = time.time()

        if now - last_acme_check >= ACME_CHECK_INTERVAL:
            current_acme_hash = get_file_hash(ACME_PATH)
            if current_acme_hash != last_acme_hash:
                logging.info('acme.json changed — extracting new certs...')
                extracted = extract_certs(ACME_PATH, CERTS_DIR)
                extracted_ref['data'] = extracted
                update_xray_inbounds(DB_PATH, extracted)
                restart_3xui()
                last_acme_hash = current_acme_hash
            else:
                logging.info('acme.json unchanged')
            last_acme_check = now


if __name__ == '__main__':
    main()