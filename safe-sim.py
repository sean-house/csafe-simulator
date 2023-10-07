# Modules
import os
import sys
from datetime import datetime, timezone
import base64
import logging
import requests
from time import sleep
from typing import Tuple
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKeyWithSerialization
from cryptography.exceptions import InvalidSignature
from settings import version, safe_data, safe_datadir, safe_keydir, server_url_base
import safe_gpio_sim


def generate_key(password: bytes, hw_id: str) -> Tuple[RSAPrivateKeyWithSerialization, bytes]:
    """
    Generate an RSA private key from scratch. File it and the public key on disk
    using the password supplied
    :param password: str
    :return: RSAPrivateKeyWithSerialization,
    """
    rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend())

    rsa_private_key_pem = rsa_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password))

    rsa_public_key = rsa_private_key.public_key()
    rsa_public_key_pem = rsa_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

    # Write both keys to disk
    # Check the directory exists first
    if not os.path.isdir(safe_keydir.format(hw_id)):
        os.mkdir(safe_keydir.format(hw_id))
    with open(os.path.join(safe_keydir.format(hw_id), 'private_key.pem'), "wb") as key_file:
        key_file.write(rsa_private_key_pem)
    with open(os.path.join(safe_keydir.format(hw_id), 'public_key.pem'), "wb") as key_file:
        key_file.write(rsa_public_key_pem)

    return rsa_private_key, rsa_public_key_pem


# def get_hardware_id() -> str:
#     """
#     Get a unique ID for the hardware this is running on
#     :return:
#     """
#     global hardware_id
#     print(os.name)
#     if 'nt' in os.name:
#         hardware_id = str(subprocess.Popen('wmic csproduct get uuid'.split()))
#         return hardware_id
#     elif 'posix' in os.name:
#         hardware = subprocess.check_output(r"cat /proc/cpuinfo | grep Hardware | cut -d ' ' -f 2",
#                                            shell=True).strip().decode('utf-8')
#         revision = subprocess.check_output(r"cat /proc/cpuinfo | grep Revision | cut -d ' ' -f 2",
#                                            shell=True).strip().decode('utf-8')
#         serial = subprocess.check_output(r"cat /proc/cpuinfo | grep Serial | cut -d ' ' -f 2",
#                                          shell=True).strip().decode('utf-8')
#         hardware_id = hardware + revision + serial
#         return hardware_id
#     else:
#         interim = subprocess.check_output("ioreg -rd1 -c IOPlatformExpertDevice | grep -E '(UUID)'",
#                                            shell=True).strip().decode('utf-8')
#
#         hardware_id = interim.split(' ')[2].strip('"')
#         return hardware_id


def get_safe_keys(hw_id: str) -> Tuple[RSAPrivateKeyWithSerialization, bytes]:
    """
    Checks if the safe keys already exists on disk and returns it if it does
    - or generates a new key if it does not.
    :return:
    """
    hardware_id_bytes = bytes(hw_id.encode('utf-8'))

    if os.path.isfile(os.path.join(safe_keydir.format(hw_id), 'private_key.pem')):
        logging.debug('Reading keys from disk')
        with open(os.path.join(safe_keydir.format(hw_id), 'private_key.pem'), "rb") as key_file:
            rsa_private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=hardware_id_bytes,
                    backend=default_backend()
            )
        with open(os.path.join(safe_keydir.format(hw_id), 'public_key.pem'), "rb") as key_file:
            rsa_public_key_pem = key_file.read()
    else:
        logging.debug('Generating new keys')
        rsa_private_key, rsa_public_key_pem = generate_key(password=hardware_id_bytes, hw_id=hw_id)
    return rsa_private_key, rsa_public_key_pem


def get_server_key(safe: str) -> bytes:
    """
    Checks if we have have the server public key on disk. Requests it from the server if not
    :return: bytes
    """
    if os.path.isfile(os.path.join(safe_keydir.format(safe), 'server_key.pem')):
        with open(os.path.join(safe_keydir.format(safe), 'server_key.pem'), "rb") as key_file:
            public_key_pem = key_file.read()
            logging.debug('Got server public key - from local store')
    else:
        server_url = server_url_base + 'api/register/'
        parameters = {'hwid': safe, 'pkey': safe_public_key_pem.decode('utf-8')}
        print(f"Getting server details for Safe id: {safe}")
        # print(safe_public_key_pem)
        #response = requests.post(server_url, json=parameters)   # POST when using Flask server
        response = requests.get(server_url, params=parameters)  # GET when using Django server
        if response.ok:
            # Write the server public key to local storage

            #print(f"Got response {response.text}")
            public_key_pem = bytes(response.text, 'utf-8')
            # if 'key' in response.json():
            #     public_key_pem = bytes(response.json()['key'], 'utf-8')
            # else:
            #     print('No "key" element in server JSON response')
            #     sys.exit(-1)
            if not public_key_pem.startswith(b'-----BEGIN PUBLIC KEY-----'):
                print('No "key" element in server JSON response')
                sys.exit(-1)
            # print(public_key_pem)
            with open(os.path.join(safe_keydir.format(safe), 'server_key.pem'), "wb") as key_file:
                key_file.write(public_key_pem)
                logging.debug(f'Safe: {safe} - Got server public key - from "server"')
        else:
            logging.error(f'Safe: {safe} - Failed to get server key with response message: {response.text}')
            sys.exit(-1)
    # Convert PEM format of public key to RSAKey format
    public_key = serialization.load_pem_public_key(public_key_pem,
                                                   backend=default_backend())
    return public_key


def check_in(status: Tuple[bool, bool, bool], safe: str) -> bool:
    """
    Checks in with the server - reports the safe status, gets authorisation to unlock
    :return: Tuple(auth_to_unlock: bool, unlock_time: datetime.datetime)
    """
    global auth_to_unlock
    global unlock_time
    now = datetime.now(timezone.utc)
    # Send status to server
    safe_message = 'STATUS,{},{},{},{},{}\n'.format(safe, now, status[0], status[1],
                                                    status[2])
    for i in range(len(event_log[safe])):
        event = event_log[safe].pop(0)
        safe_message = safe_message + 'EVENT,{},{}\n'.format(event[0], event[1])
    logging.debug(f'Safe: {safe} - Safe message = {safe_message}')
    # Sign safe message
    safe_message_bin = bytes(safe_message.encode('UTF-8'))
    safe_message_sig = safe_private_key.sign(
            safe_message_bin,
            padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256())
    safe_message_sig_64 = base64.urlsafe_b64encode(safe_message_sig)
    # Encrypt safe message
    safe_message_enc = server_public_key.encrypt(
            safe_message_bin,
            padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
            ))
    safe_message_enc_64 = base64.urlsafe_b64encode(safe_message_enc)
    server_url = server_url_base + 'api/checkin/'
    parameters = \
        {
            'hwid': safe, 'sig': str(safe_message_sig_64, 'utf-8'),
            'msg': str(safe_message_enc_64, 'utf-8')
        }
    print(f"Checkin - submitting {parameters}")

    # Submit to server and get response
    try:
        response = requests.get(server_url, params=parameters)
        if response.ok:
            logging.debug(f'Safe: {safe} - CheckIn response: {response.text}')
        else:
            logging.error(f'Safe: {safe} - CheckIn error {response.content}')

        # Extract message and sig from the response JSON object
        # parms = response.json()
        # if all(map(lambda x: x in parms, ['msg', 'sig'])):
        #     server_message_enc_64 = parms['msg']
        #     server_message_sig_64 = parms['sig']
        # else:
        #     return False

        # Split response into message and sig
        if '***PART***' in response.text:
            server_message_enc_64, server_message_sig_64 = response.text.split('***PART***')
        else:
            return False

        # Decrypt
        try:
            plaintext = safe_private_key.decrypt(
                    base64.urlsafe_b64decode(server_message_enc_64),
                    padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                    ))
            decrypt_success = True
        except ValueError:
            logging.error(f"Safe: {safe} - Decrypting error")
            decrypt_success = False

        # Check signature if decryption was successful
        if decrypt_success:
            try:
                server_public_key.verify(
                        base64.urlsafe_b64decode(server_message_sig_64),
                        plaintext,
                        padding.PSS(
                                mgf=padding.MGF1(hashes.SHA256()),
                                salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256())
                signature_valid = True
            except InvalidSignature as e:
                logging.info(f'Safe: {safe} - Invalid signature : {e}')
                signature_valid = False
        else:
            signature_valid = False

        print(f'Signature valid: {signature_valid}')

        if signature_valid:
            # Interpret message and test message validity
            p1_validity = False
            p2_validity = False
            now = datetime.now(timezone.utc)
            plaintext = str(plaintext.decode('utf-8'))
            message_parts = plaintext.split('\n')
            print(message_parts)
            if len(message_parts) >= 2:
                if message_parts[0].startswith('Auth_to_unlock'):
                    m0_parts = message_parts[0].split(':', 2)
                    auth_tstamp = datetime.strptime(m0_parts[2], '%Y-%m-%d %H:%M:%S.%f%z')
                    auth_tstamp = auth_tstamp.replace(tzinfo=timezone.utc)  # Localize the returned timestamp to UTC
                    if m0_parts[1] == 'TRUE':
                        auth_to_unlock = True
                        print(f"m0_parts = {m0_parts[2]}")
                        if auth_tstamp < now:
                            p1_validity = True
                    elif m0_parts[1] == 'FALSE':
                        auth_to_unlock = False
                        if auth_tstamp < now:
                            p1_validity = True
                if message_parts[1].startswith('Unlock_time'):
                    # If no unlock time given, default to unlock now as a safety feature
                    unlock_time_str = message_parts[1][12:]
                    if unlock_time_str == '':
                        unlock_time = now
                        logging.error(f'Safe: {safe} - Server message contains no unlock time - setting to now: {now}')
                    else:
                        if '.' in unlock_time_str:  # The time component has microseconds
                            unlock_time = datetime.strptime(unlock_time_str, '%Y-%m-%d %H:%M:%S.%f%z')
                        else:
                            unlock_time = datetime.strptime(unlock_time_str, '%Y-%m-%d %H:%M:%S')
                    unlock_time = unlock_time.replace(tzinfo=timezone.utc)
                    p2_validity = True
                if p1_validity and p2_validity:
                    validity = True
                    if unlock_time < now:
                        auth_to_unlock = True
                else:
                    validity = False
                if len(message_parts) > 2:
                    if message_parts[2].startswith('Settings'):
                        set_settings(message_parts[2], safe)
                    elif message_parts[2].startswith('Terminate'):
                        if message_parts[2].endswith('TRUE') and operating_mode == logging.DEBUG:
                            # Means for server to terminate safe program - only works in debug mode
                            logging.debug(f'Safe: {safe} - Terminate message received - exiting app')
                            safe_gpio_sim.destroy_gpio()
                            print(f'Safe: {safe} - Terminate at server request\n')
                            sys.exit(0)
                    else:
                        validity = False
            else:
                validity = False

        else:
            validity = False
        if not validity:
            # if signature is invalid effectively prevent unlock
            auth_to_unlock = False
            validity = False
            unlock_time = datetime(2199, 12, 31, 12, 0, 0, 0)
            log_event('INVALID_MSG_RECD', safe)
    except OSError as e:
        logging.error('Request error in CheckIn - {}'.format(e))
        safe_gpio_sim.set_lights('ERR', safe)
        validity = False
    return validity


def set_settings(settings_msg: str, safe: str):
    global scanfreq
    global reportfreq
    global proximityunit
    global displayproximity
    settings_changed = False
    settings_parts = settings_msg.split(':')
    if len(settings_parts) == 5:  # Only act if there are exactly 5 settings parts
        if '=' in settings_parts[1]:
            s1_parts = settings_parts[1].split('=')
            if s1_parts[0] == 'SCANFREQ':
                new_scanfreq = int(s1_parts[1])
                if new_scanfreq != scanfreq:
                    scanfreq = new_scanfreq
                    settings_changed = True
        if '=' in settings_parts[2]:
            s2_parts = settings_parts[2].split('=')
            if s2_parts[0] == 'REPORTFREQ':
                new_reportfreq = int(s2_parts[1])
                if new_reportfreq != reportfreq:
                    reportfreq = new_reportfreq
                    settings_changed = True
        if '=' in settings_parts[3]:
            s3_parts = settings_parts[3].split('=')
            if s3_parts[0] == 'PROXIMITYUNIT':
                new_proximityunit = s3_parts[1]
                if new_proximityunit != proximityunit:
                    proximityunit = new_proximityunit
                    settings_changed = True
        if '=' in settings_parts[4]:
            s4_parts = settings_parts[4].split('=')
            if s4_parts[0] == 'DISPLAYPROXIMITY':
                new_displayproximity = s4_parts[1] == 'TRUE'
                if new_displayproximity != displayproximity:
                    displayproximity = new_displayproximity
                    settings_changed = True
        if settings_changed:
            logging.debug(f'New settings = {scanfreq}, {reportfreq}, {proximityunit}, {displayproximity}')
            log_event(f'Settings{scanfreq}-{reportfreq}-{proximityunit}-{displayproximity}', safe)
            # Update the file of settings
            with open(os.path.join(safe_datadir.format(safe), 'settings.txt'), 'w') as fo:
                fo.write(f"{scanfreq},{reportfreq},{proximityunit},{displayproximity},{auth_to_unlock}," +
                         unlock_time.strftime('%Y,%m,%d,%H,%M,%S,%f') + '\n')

    return


def show_lights(now: datetime, safe: str):
    """
    Display lights on the safe showing the auth to unlock 'G', and up to 5 lights 'R'
    giving proximity to unlock time in proximity units.

    :param now:
    :return: None
    """
    global auth_to_unlock
    global unlock_time
    global lock_engaged
    interval_seconds = {
        'M': 60,
        'H': 60 * 60,
        'D': 60 * 60 * 24,
        'W': 60 * 60 * 24 * 7
    }
    if auth_to_unlock:
        safe_gpio_sim.set_lights('G', safe)
        print('Safe lights set to "G"')
        if lock_engaged:
            print('Unlocking safe')
            safe_gpio_sim.unlock_safe(safe)
            lock_engaged = False
    else:
        # If the lock is not already engaged - engage it
        if not lock_engaged:
            safe_gpio_sim.lock_safe(safe)
            lock_engaged = True
        if displayproximity:
            time_to_go = unlock_time - now
            seconds_to_go = time_to_go.days * (24 * 60 * 60) + time_to_go.seconds
            num_intervals = int(seconds_to_go / interval_seconds[proximityunit]) + 1
            if num_intervals > 5:
                num_intervals = 5
            safe_gpio_sim.set_lights(str(num_intervals) + 'R', safe)
            print('Diagnostic message:  Safe lights set to {}R'.format(num_intervals))
        else:
            safe_gpio_sim.set_lights('OFF', safe)
    return


def log_event(event: str, safe: str) -> None:
    """
    Adds event to event log
    :param event:
    :return:
    """
    global event_log
    event_log[safe].append((datetime.now(timezone.utc), event))
    return


# def spin_lights():
#     seq = ['OFF', '5R', '4R', '3R', '2R', '1R', 'OFF', '1R', '2R', '3R', '4R', '5R',
#            'ERR', 'OFF', 'ERR', 'OFF', 'G', 'OFF', 'G', 'OFF']
#     for i in seq:
#         safe_gpio_sim.set_lights(i)
#         sleep(0.1)
#     print('Diagnostic message:  Spin lights')
#
#
# def dissuasion():
#     seq = ['OFF', 'ERR', 'OFF', '5R', 'OFF', 'ERR', 'OFF', '5R', 'OFF', 'ERR', 'OFF']
#     for i in seq:
#         safe_gpio_sim.set_lights(i)
#         sleep(0.1)
#     print('Diagnostic message:  Dissuasion')
#
#
# def celebration():
#     seq = ['OFF', '5R', '4R', '3R', '2R', '1R', 'OFF', 'G', 'OFF', 'G', 'OFF', 'G', 'OFF',
#            'G', 'OFF', 'G', 'OFF', 'G', 'OFF']
#     for i in seq:
#         safe_gpio_sim.set_lights(i)
#         sleep(0.1)
#     print('Diagnostic message:  Celebration')


def button_pushed(channel, safe):
    """
    Called when the safe button is pressed
    :return:
    """
    global lock_engaged
    if auth_to_unlock:
        print('Unlocking permitted')
        logging.debug('Button pressed - unlocking')
        # celebration()
        if lock_engaged:
            safe_gpio_sim.unlock_safe(safe)
            lock_engaged = False
    else:
        print('Unlocking not permitted')
        logging.debug('Button pressed - not permitted to unlock')
        # dissuasion()
        show_lights(datetime.now(timezone.utc), safe)
        if not lock_engaged:
            safe_gpio_sim.lock_safe(safe)
            lock_engaged = True
    return


def mainloop(safe: str) -> None:
    """
    Main-loop - repeat once when in simulation mode
    :return: None
    """
    global event_log
    global auth_to_unlock
    global unlock_time
    global scan_number
    print(f"Starting mainloop for {safe}")
    unlock_status = 'indeterminate'
    now = datetime.now(timezone.utc)
    # Get safe status
    safe_status = safe_gpio_sim.get_safe_status(safe)
    # Log an event if safe status changes
    if not all(safe_status) and unlock_status != 'open':
        log_event('SAFE_OPEN', safe)
        unlock_status = 'open'
    elif all(safe_status) and unlock_status != 'locked':
        log_event('SAFE_LOCKED', safe)
        unlock_status = 'locked'
    if not auth_to_unlock and unlock_time < now:
        auth_to_unlock = True
    if scan_number[safe] % reportfreq == 0:
        scan_number[safe] = 0
        # Report status, get latest server message
        msg_valid = check_in(safe_status, safe)
        logging.debug(f'Safe: {safe} - Message valid: {msg_valid}, '
                      f'Authorised to unlock: {auth_to_unlock},  '
                      f'Unlock time: {unlock_time}')
    show_lights(now, safe)
    scan_number[safe] += 1


if __name__ == '__main__':
    print('Version = {}'.format(version))

    # Set up logging
    # Remove any existing handlers first
    operating_mode = logging.DEBUG
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
    logging.basicConfig(filename=os.path.join(safe_data, 'safe-simulator.log'),
                        format='%(asctime)s : %(levelname)s :%(message)s',
                        level=operating_mode)
    logging.debug('\n\n*********** Starting operation ****************')
    print('Starting')

    scan_number = {}
    event_log = {}

    # hardware_id = get_hardware_id()
    safes = [dir for dir in os.listdir(safe_data) if os.path.isdir(os.path.join(safe_data, dir))]
    print(safes)

    # set initial scan numbers to zero - allow one scan number for each safe being simulated.
    for safe in safes:
        scan_number[safe] = 0

    # Make a while True loop once everything is working

    for current_safe in safes:
        # Read settings - per safe
        # while True:
        with open(os.path.join(safe_datadir.format(current_safe), 'settings.txt'), 'r') as fi:
            parms = fi.readline().strip().split(',')
            print(f"Current safe = {current_safe} - {parms}")
            scanfreq = int(parms[0])  # seconds
            reportfreq = int(parms[1])  # number of scanfreq periods
            proximityunit = parms[2]
            displayproximity = parms[3] == 'True'
            auth_to_unlock = parms[4] == 'True'
            unlock_time = datetime(int(parms[5]),
                                   int(parms[6]),
                                   int(parms[7]),
                                   int(parms[8]),
                                   int(parms[9]),
                                   int(parms[10]),
                                   int(parms[11])).replace(tzinfo=timezone.utc)
            # Need to work on the bits below
            event_log[current_safe] = []
            log_event('STARTING_OPERATION', current_safe)

            # safe_gpio.setup_gpio(button_pushed)
            # safe_gpio.lock_safe()
            lock_engaged = all(safe_gpio_sim.get_safe_status(current_safe))

            # spin_lights()

            safe_private_key, safe_public_key_pem = get_safe_keys(current_safe)
            server_public_key = get_server_key(current_safe)

            mainloop(current_safe)
        sleep(10)
    print('Simulator terminating')
