#!/usr/bin/python3
import os
import yaml
import struct
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
DEFAULT_USER = "nobody"
debug = True

def get_password_hash(pamh, settings, target_len):
  if debug: print('pamh.authtok:', pamh.authtok)
  if debug: print('pamh.oldauthtok:', pamh.oldauthtok)
  password = input('password: ')
  if settings['password-hash'] == 'SHA256':
    digest = hashes.Hash(hashes.SHA256())
  elif settings['password-hash'] == 'SHA1':
    digest = hashes.Hash(hashes.SHA1())
  elif settings['password-hash'] == 'SHA512':
    digest = hashes.Hash(hashes.SHA512())
  elif settings['password-hash'] == 'SHA224':
    digest = hashes.Hash(hashes.SHA224())
  elif settings['password-hash'] == 'SHA384':
    digest = hashes.Hash(hashes.SHA384())
  elif settings['password-hash'] == 'SHA512_224':
    digest = hashes.Hash(hashes.SHA512_224())
  elif settings['password-hash'] == 'SHA512_256':
    digest = hashes.Hash(hashes.SHA512_256())
  elif settings['password-hash'] == 'SHA3_224':
    digest = hashes.Hash(hashes.SHA3_224())
  elif settings['password-hash'] == 'SHA3_256':
    digest = hashes.Hash(hashes.SHA3_256())
  elif settings['password-hash'] == 'SHA3_384':
    digest = hashes.Hash(hashes.SHA3_384())
  elif settings['password-hash'] == 'SHA3_512':
    digest = hashes.Hash(hashes.SHA3_512())
  digest.update(password.encode('utf-8'))
  password_hash = digest.finalize()
  if debug: print('password_hash.hex():', password_hash.hex())
  if debug: print(len(password_hash))
  while len(password_hash) < target_len:
    password_hash = password_hash + b'\x00'
  if len(password_hash) > target_len:
    password_hash = password_hash[0:target_len]
  if debug: print(len(password_hash))
  if debug: print('password_hash.hex():', password_hash.hex())
  return password_hash

def pam_sm_authenticate(pamh, flags, argv):
  try:
    user = pamh.get_user(None)
  except pamh.exception as e:
    return e.pam_result
  if debug: print('user:', user)
  if user == None:
    pam.user = DEFAULT_USER
  chain_yaml = yaml.safe_load(open(argv[1], 'r'))
  if not user in chain_yaml:
    return pamh.PAM_USER_UNKNOWN
  chain = chain_yaml[user]
  if debug: print('chain:', chain)
  settings = chain['settings']
  if settings['cipher'] == 'AES256':
    cipher = Cipher(algorithms.AES256(get_password_hash(pamh, settings, 32)), modes.CTR(bytes.fromhex(chain['nonce'])))
    decryptor = cipher.decryptor()
    monstrosity = decryptor.update(bytes.fromhex(chain['encrypted-monstrosity'])) + decryptor.finalize()
  if debug: print('monstrosity.hex():', monstrosity.hex())
  data_array = []
  pointer_array = []
  pointer_bytes = settings['pointer-bits'] // 8
  ball_size = os.path.getsize(settings['ball'])
  if debug: print('ball_size:', ball_size)
  ball = open(settings['ball'], 'rb')
  for i in range(0, settings['pointer-data-pairs']):
    if debug: print('i', i)
    index = i * pointer_bytes
    if debug: print('index:', index)
    pointer_array.append(monstrosity[index : index + pointer_bytes])
    if debug: print("pointer_array[i].hex():", pointer_array[i].hex())
    if settings['pointer-bits'] == 32:
      unpacked_pointer = struct.unpack('>I', pointer_array[i])[0]
    elif settings['pointer-bits'] == 64:
      unpacked_pointer = struct.unpack('>Q', pointer_array[i])[0]
    else:
      return pamh.PAM_AUTH_ERR
    if debug: print('unpacked_pointer:', unpacked_pointer)
    ball.seek(unpacked_pointer % ball_size)
    data_array.append(ball.read(settings['data-length']))
    if debug: print('data_array[i].hex():', data_array[i].hex())
  data_string = b''.join(data_array)
  if debug: print('data_string.hex():', data_string.hex())
  if settings['data-hash'] == 'SHA256':
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data_string)
    data_hash = digest.finalize()
    if debug: print('data_hash.hex():', data_hash.hex())
  data_hash_stored = monstrosity[ pointer_bytes * settings['pointer-data-pairs'] : ]
  if debug: print('data_hash_stored.hex():', data_hash_stored.hex())
  if data_hash == data_hash_stored:
    return pamh.PAM_SUCCESS
  return pamh.PAM_AUTH_ERR

def pam_sm_setcred(pamh, flags, argv):
  return pamh.PAM_SUCCESS

def pam_sm_acct_mgmt(pamh, flags, argv):
  return pamh.PAM_SUCCESS

def pam_sm_open_session(pamh, flags, argv):
  return pamh.PAM_SUCCESS

def pam_sm_close_session(pamh, flags, argv):
  return pamh.PAM_SUCCESS

def pam_sm_chauthtok(pamh, flags, argv):
  if debug: print('pam_sm_chauthtok')
  if debug: print('hex(flags):', hex(flags))
  if flags & pamh.PAM_PRELIM_CHECK != 0:
    return pamh.PAM_SUCCESS
  if flags & pamh.PAM_UPDATE_AUTHTOK == 0:
    return pamh.PAM_AUTHTOK_ERR
  if debug: print('argv:', argv)
  user = pamh.get_user(None)
  settings = yaml.safe_load(open(argv[2], 'r'))
  if debug: print('settings:', settings)
  ball_size = os.path.getsize(settings['ball'])
  if debug: print('ball_size:', ball_size)
  ball = open(settings['ball'], 'rb')
  pointer_array = []
  data_array = []
  for i in range(0, settings['pointer-data-pairs']):
    if debug: print('i:', i)
    pointer = secrets.randbits(settings['pointer-bits'])
    if debug: print('pointer:', pointer)
    if settings['pointer-bits'] == 32:
      packed_pointer = struct.pack('>I', pointer)
    elif settings['pointer-bits'] == 64:
      packed_pointer = struct.pack('>Q', pointer)
    else:
      return pamh.PAM_AUTHTOK_ERR
    pointer_array.append(packed_pointer)
    if debug: print('packed_pointer:', packed_pointer)
    ball.seek(pointer % ball_size)
    data_array.append(ball.read(settings['data-length']))
    if debug: print('data_array[i].hex():', data_array[i].hex())
  data_string = b''.join(data_array)
  if debug: print('data_string.hex():', data_string.hex())
  pointer_string = b''.join(pointer_array)
  if debug: print('pointer_string.hex()', pointer_string.hex())
  if settings['data-hash'] == 'SHA256':
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data_string)
    data_hash = digest.finalize()
    if debug: print('data_hash.hex():', data_hash.hex())
  monstrosity = b''.join([pointer_string, data_hash])
  if debug: print('monstrosity.hex():', monstrosity.hex())
  encrypted_monstrosity = None
  if settings['cipher'] == 'AES256':
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES256(get_password_hash(pamh, settings, 32)), modes.CTR(iv))
    encryptor = cipher.encryptor()
    encrypted_monstrosity = encryptor.update(monstrosity) + encryptor.finalize()
  if debug: print('encrypted_monstrosity.hex():', encrypted_monstrosity.hex())
  entry = {
    'settings': settings,
    'encrypted-monstrosity': encrypted_monstrosity.hex(),
    'nonce': iv.hex(),
  }
  chain = yaml.safe_load(open(argv[1], 'r'))
  if debug: print('chain:', chain)
  if chain == None:
    chain = {}
  chain[user] = entry
  yaml.dump(chain, open(argv[1], 'w'))
  return pamh.PAM_SUCCESS

