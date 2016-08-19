"""
This script is intended to be executed as `python3 -i <path-to-script>`
"""


import json
import os

import lightu2f


APPID = 'https://jong.sh'
registered_keys = []
ticket1 = os.urandom(32)
ticket2 = os.urandom(32)


def generate_registration_request():
    global request
    khs = [kh for kh, pk, cnt in registered_keys]
    request = lightu2f.generate_enrollment_request(APPID, ticket1, khs)
    print('''// To send the request to the U2F client in Chrome

var request = %s;
p.postMessage(request);
''' % request)


def process_registration_response(response):
    global keyhandle, publickey, facetid
    if type(response) is not str:
        response = json.dumps(response)
    try:
        facetid, keyhandle, publickey, cert, cidinfo = lightu2f.process_enrollment_response(APPID, ticket1, response)
    except ValueError:
        print()
        print('the provided enrollment response message is invalid')
    else:
        print()
        print('the provided enrollment response message looks valid:')
        print('keyhandle =', keyhandle.hex())
        print('publickey =', publickey.hex())
        print('facetid =', facetid)
        store_new_key_info(keyhandle, publickey)


def store_new_key_info(keyhandle, publickey):
    print()
    global registered_keys
    if any(keyhandle == kh for kh, pk, cnt in registered_keys):
        print('Error: the keyhandle is already registered:\n%s' % keyhandle.hex())
    else:
        registered_keys.append([keyhandle, publickey, None])
        print('Key info stored successfully')
    print()


def generate_authentication_request():
    global request
    request = lightu2f.generate_idassertion_request(APPID, ticket2, registered_keys)
    print()
    print('''// To send the request to the U2F client in Chrome

var request = %s;
p.postMessage(request);
''' % request)


def process_authentication_response(response):
    global facetid, kh, pk, cnt_old, cnt_new, cidinfo
    if type(response) is not str:
        response = json.dumps(response)
    try:
        (
            facetid, kh, pk, cnt_old, cnt_new, cidinfo
        ) = lightu2f.process_idassertion_response(APPID, ticket2, response)
    except ValueError:
        print()
        print('the provided enrollment response message is invalid')
    else:
        print()
        print('the provided enrollment response message looks valid:')
        print('facetid =', facetid)
        print('kh =', kh.hex())
        print('pk =', pk.hex())
        print('cnt_old =', cnt_old)
        print('cnt_new =', cnt_new)
        update_existing_key_into(kh, pk, cnt_old, cnt_new)


def update_existing_key_into(kh, pk, cnt_old, cnt_new):
    print()
    for idx, (k, p, c) in enumerate(registered_keys):
        if kh == k and pk == p:
            if cnt_old == c:
                registered_keys[idx][2] = cnt_new
                print('Key info updated successfully')
            else:
                print('Error: old counter does not match')
                print('the database shows cnt_old = %d' % c)
            return
    print('Error: no such key exists')
    print()


print('''// JavaScript code for Google Chrome to interact with U2F Client:

(()=>{
  var ID = 'kmendfapggjehodndflmmgagdbamhnfd';
  var i = 1, p = window.p = chrome.runtime.connect(ID);
  p.onMessage.addListener((response)=>{
    console.log('a response from U2F Client is saved at `r' + i + '`');
    window['r' + i] = JSON.stringify(response.responseData);
    ++i;
  });
  console.log('Use p.postMessage(...) to make U2F requests');
})();
''')
