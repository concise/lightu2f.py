import newlib
import os


registered_keys = []
ticket1 = os.urandom(32)
ticket2 = os.urandom(32)


def gen_enr_request():
    khs = [kh for kh, pk, cnt in registered_keys]
    request = newlib.generate_enrollment_request('https://jong.sh', ticket1, registered_keys)
    print('''// To send the request to the U2F client in Chrome

var request = %s;

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

p.postMessage(request);
''' % request)


def proc_enr_response(response):
    global keyhandle, publickey, facetid
    if type(response) is not str:
        import json
        response = json.dumps(response)
    try:
        facetid, keyhandle, publickey, cert, cidinfo = newlib.process_enrollment_response('https://jong.sh', ticket1, response)
    except ValueError:
        print()
        print('the provided enrollment response message is invalid')
    else:
        print()
        print('the provided enrollment response message is valid')
        print('keyhandle =', keyhandle.hex())
        print('publickey =', publickey.hex())
        print('facetid =', facetid)


def store_new_key_into_global(keyhandle, publickey):
    global registered_keys
    if any(keyhandle == kh for kh, pk, cnt in registered_keys):
        print('Error: the keyhandle %s is already registered' % keyhandle.hex())
    else:
        registered_keys.append((keyhandle, publickey, None))
        print('key info stored successfully')


import sys;sys.exit(0)


def step3():
    ...


already_registered_keys = [(bytes.fromhex('1b619323d95a9bc9215ecc87c50d32f3f3c7ee01c0e45d04c4b612d6fa91367a4774d2184e6a053a2748fc67b33f9cf524ebc2a3aed28ff6a20569e908f4b107'),bytes.fromhex('04de612c5ee0982bdd4a36a806ca33cf94d901da022793a4da7b739bfb439400301b162fd84dcc92a307077fee7c34c75edd2457cf7a5bcb82b5dcd8aaf41b7959'),None)]
tid = bytes.fromhex('8d26eee6f0b1dcd2052963b6e809281bdd22871c76e881856299cd5dbaaf76b1')
request = newlib.generate_idassertion_request('https://jong.sh', tid, already_registered_keys)
print(request)

'''

{"signRequests":[{"appId":"https://jong.sh","challenge":"jSbu5vCx3NIFKWO26AkoG90ihxx26IGFYpnNXbqvdrEE3mEsXuCYK91KNqgGyjPPlNkB2gInk6Tae3Ob-0OUADAbFi_YTcySowcHf-58NMde3SRXz3pby4K13Niq9Bt5WQAAAAAA","keyHandle":"G2GTI9lam8khXsyHxQ0y8_PH7gHA5F0ExLYS1vqRNnpHdNIYTmoFOidI_GezP5z1JOvCo67Sj_aiBWnpCPSxBw","version":"U2F_V2"}],"type":"u2f_sign_request"}



p.postMessage({"signRequests":[{"appId":"https://jong.sh","challenge":"jSbu5vCx3NIFKWO26AkoG90ihxx26IGFYpnNXbqvdrEE3mEsXuCYK91KNqgGyjPPlNkB2gInk6Tae3Ob-0OUADAbFi_YTcySowcHf-58NMde3SRXz3pby4K13Niq9Bt5WQAAAAAA","keyHandle":"G2GTI9lam8khXsyHxQ0y8_PH7gHA5F0ExLYS1vqRNnpHdNIYTmoFOidI_GezP5z1JOvCo67Sj_aiBWnpCPSxBw","version":"U2F_V2"}],"type":"u2f_sign_request"})

>>>

{"keyHandle":"G2GTI9lam8khXsyHxQ0y8_PH7gHA5F0ExLYS1vqRNnpHdNIYTmoFOidI_GezP5z1JOvCo67Sj_aiBWnpCPSxBw","clientData":"eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZ2V0QXNzZXJ0aW9uIiwiY2hhbGxlbmdlIjoialNidTV2Q3gzTklGS1dPMjZBa29HOTBpaHh4MjZJR0ZZcG5OWGJxdmRyRUUzbUVzWHVDWUs5MUtOcWdHeWpQUGxOa0IyZ0luazZUYWUzT2ItME9VQURBYkZpX1lUY3lTb3djSGYtNThOTWRlM1NSWHozcGJ5NEsxM05pcTlCdDVXUUFBQUFBQSIsIm9yaWdpbiI6Imh0dHBzOi8vam9uZy5zaCIsImNpZF9wdWJrZXkiOiJ1bnVzZWQifQ","signatureData":"AQAAAAAwQwIfWQlWaaTBfjCunf59AA34L_Y19LWbPWGVe8hXkWLt-AIgRX_B4cyQFQx1sA0TRWzEzs8cmXMVQ7b8a0E75b-BEsI"}

'''

tid = bytes.fromhex('8d26eee6f0b1dcd2052963b6e809281bdd22871c76e881856299cd5dbaaf76b1')
response = '{"keyHandle":"G2GTI9lam8khXsyHxQ0y8_PH7gHA5F0ExLYS1vqRNnpHdNIYTmoFOidI_GezP5z1JOvCo67Sj_aiBWnpCPSxBw","clientData":"eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZ2V0QXNzZXJ0aW9uIiwiY2hhbGxlbmdlIjoialNidTV2Q3gzTklGS1dPMjZBa29HOTBpaHh4MjZJR0ZZcG5OWGJxdmRyRUUzbUVzWHVDWUs5MUtOcWdHeWpQUGxOa0IyZ0luazZUYWUzT2ItME9VQURBYkZpX1lUY3lTb3djSGYtNThOTWRlM1NSWHozcGJ5NEsxM05pcTlCdDVXUUFBQUFBQSIsIm9yaWdpbiI6Imh0dHBzOi8vam9uZy5zaCIsImNpZF9wdWJrZXkiOiJ1bnVzZWQifQ","signatureData":"AQAAAAAwQwIfWQlWaaTBfjCunf59AA34L_Y19LWbPWGVe8hXkWLt-AIgRX_B4cyQFQx1sA0TRWzEzs8cmXMVQ7b8a0E75b-BEsI"}'

facetid, kh, pk, cnt_old, cnt_new, cidinfo = newlib.process_idassertion_response('https://jong.sh', tid, response)
print('facetid =', facetid); print('kh =', kh.hex()); print('pk =', pk.hex()); print('cnt_old =', cnt_old); print('cnt_new =', cnt_new)

'''

facetid = https://jong.sh
kh = 1b619323d95a9bc9215ecc87c50d32f3f3c7ee01c0e45d04c4b612d6fa91367a4774d2184e6a053a2748fc67b33f9cf524ebc2a3aed28ff6a20569e908f4b107
pk = 04de612c5ee0982bdd4a36a806ca33cf94d901da022793a4da7b739bfb439400301b162fd84dcc92a307077fee7c34c75edd2457cf7a5bcb82b5dcd8aaf41b7959
cnt_old = None
cnt_new = 0

'''

response_2 = '{"keyHandle":"G2GTI9lam8khXsyHxQ0y8_PH7gHA5F0ExLYS1vqRNnpHdNIYTmoFOidI_GezP5z1JOvCo67Sj_aiBWnpCPSxBw","clientData":"eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZ2V0QXNzZXJ0aW9uIiwiY2hhbGxlbmdlIjoialNidTV2Q3gzTklGS1dPMjZBa29HOTBpaHh4MjZJR0ZZcG5OWGJxdmRyRUUzbUVzWHVDWUs5MUtOcWdHeWpQUGxOa0IyZ0luazZUYWUzT2ItME9VQURBYkZpX1lUY3lTb3djSGYtNThOTWRlM1NSWHozcGJ5NEsxM05pcTlCdDVXUUFBQUFBQSIsIm9yaWdpbiI6Imh0dHBzOi8vam9uZy5zaCIsImNpZF9wdWJrZXkiOiJ1bnVzZWQifQ","signatureData":"AQAAAAEwRQIhAKkT7fQJPlAlNQBrn8sVtIwS6Bx5BkuWo-x_wjwZ7x50AiAr3Tjx5bqgfqjIdWVH45v9h0VTy3tJ5SD4hUyDNyiXag"}'

'''

facetid = https://jong.sh
kh = 1b619323d95a9bc9215ecc87c50d32f3f3c7ee01c0e45d04c4b612d6fa91367a4774d2184e6a053a2748fc67b33f9cf524ebc2a3aed28ff6a20569e908f4b107
pk = 04de612c5ee0982bdd4a36a806ca33cf94d901da022793a4da7b739bfb439400301b162fd84dcc92a307077fee7c34c75edd2457cf7a5bcb82b5dcd8aaf41b7959
cnt_old = None
cnt_new = 1

'''
