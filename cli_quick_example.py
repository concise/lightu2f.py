#!/usr/bin/env python3
#
# python3 example_enroll.py ticket_id comman-separated-key-handle-list-in-hex-format
#

from newlib import *
from os import urandom
import sys

args = sys.argv[1:]

if len(args) != 2:
    print('Usage:')
    print('\tcli_quick_example.py arg1 arg2')
    print()
    print('\targ1 = <your application identity>')
    print('\targ2 = <a comma-separated list of hex key handles>')
    sys.exit(1)

app_id = args[0]

if args[1].strip() != '':
    already_registered_key_handles = [bytes.fromhex(kh_hex) for kh_hex in args[1].strip().split(',')]
else:
    already_registered_key_handles = []

print(app_id, already_registered_key_handles)
sys.exit(0)





# Transaction 1: Let's register a new U2F security key

ticket = urandom(32)
already_registered_keys = []
request = generate_enrollment_request('https://jong.sh', ticket, already_registered_keys)
print('ticket =', repr(ticket.hex()))
print('request =', request)

'''
Let's say we get:

ticket = '20d0fb8496b170295669297625ebeb0912b29a53a1a3bbb2a1a10f24229673aa'
request = {"registerRequests":[{"appId":"https://jong.sh","challenge":"IND7hJaxcClWaSl2JevrCRKymlOho7uyoaEPJCKWc6o","version":"U2F_V2"}],"signRequests":[],"type":"u2f_register_request"}

Now open Google Chrome and go to https://jong.sh/404
Run code:

(()=>{
  // run google-chrome with --show-component-extension-options to see
  // the extension ID of "CryptoTokenExtension" builtin extension
  var ID = 'kmendfapggjehodndflmmgagdbamhnfd';
  var i = 1, p = window.p = chrome.runtime.connect(ID);
  p.onMessage.addListener((response)=>{
    console.log('a response from U2F Client is saved at `r%d`', i);
    window['r' + i] = JSON.stringify(response.responseData);
    i = (i + 1) % 10;
  });
  console.log('Use p.postMessage(...) to make U2F requests');
})();

p.postMessage({"registerRequests":[{"appId":"https://jong.sh","challenge":"IND7hJaxcClWaSl2JevrCRKymlOho7uyoaEPJCKWc6o","version":"U2F_V2"}],"signRequests":[],"type":"u2f_register_request"})

see "a response from U2F Client is saved at `r1`"

copy(r1)

'''

response = '{"registrationData":"BQTeYSxe4Jgr3Uo2qAbKM8-U2QHaAieTpNp7c5v7Q5QAMBsWL9hNzJKjBwd_7nw0x17dJFfPelvLgrXc2Kr0G3lZQBthkyPZWpvJIV7Mh8UNMvPzx-4BwORdBMS2Etb6kTZ6R3TSGE5qBTonSPxnsz-c9STrwqOu0o_2ogVp6Qj0sQcwggJEMIIBLqADAgECAgR4wN8OMAsGCSqGSIb3DQEBCzAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowKjEoMCYGA1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMjAyNTkwNTkzNDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLW4cVyD_f4OoVxFd6yFjfSMF2_eh53K9Lg9QNMg8m-t5iX89_XIr9g1GPjbniHsCDsYRYDHF-xKRwuWim-6P2-jOzA5MCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS4xMBMGCysGAQQBguUcAgEBBAQDAgUgMAsGCSqGSIb3DQEBCwOCAQEAPvar9kqRawv5lJON3JU04FRAAmhWeKcsQ6er5l2QZf9h9FHOijru2GaJ0ZC5UK8AelTRMe7wb-JrTqe7PjK3kgWl36dgBDRT40r4RMN81KhfjFwthw4KKLK37UQCQf2zeSsgdrDhivqbQy7u_CZYugkFxBskqTxuyLum1W8z6NZT189r1QFUVaJll0D33MUcwDFgnNA-ps3pOZ7KCHYykHY_tMjQD1aQaaElSQBq67BqIaIU5JmYN7Qp6B1-VtM6VJLdOhYcgpOVQIGqfu90nDpWPb3X26OVzEc-RGltQZGFwkN6yDrAZMHL5HIn_3obd8fV6gw2fUX2ML2ZjVmybjBFAiEAsX9INchmn1zOxrdnETAP5p8w_gDiBixTfBHgB1jODP8CID7uRhZcZX8-0MAJVlfMCreA0BH7DEZNsQF4rB96ofYy","appId":"https://jong.sh","challenge":"IND7hJaxcClWaSl2JevrCRKymlOho7uyoaEPJCKWc6o","version":"U2F_V2","clientData":"eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZmluaXNoRW5yb2xsbWVudCIsImNoYWxsZW5nZSI6IklORDdoSmF4Y0NsV2FTbDJKZXZyQ1JLeW1sT2hvN3V5b2FFUEpDS1djNm8iLCJvcmlnaW4iOiJodHRwczovL2pvbmcuc2giLCJjaWRfcHVia2V5IjoidW51c2VkIn0"}'
ticket = bytes.fromhex('20d0fb8496b170295669297625ebeb0912b29a53a1a3bbb2a1a10f24229673aa')
facetid, keyhandle, publickey, *_ = process_enrollment_response('https://jong.sh', ticket, response)
print('facetid =', facetid)
print('keyhandle =', keyhandle.hex())
print('publickey =', publickey.hex())

'''
facetid = https://jong.sh
keyhandle = 1b619323d95a9bc9215ecc87c50d32f3f3c7ee01c0e45d04c4b612d6fa91367a4774d2184e6a053a2748fc67b33f9cf524ebc2a3aed28ff6a20569e908f4b107
publickey = 04de612c5ee0982bdd4a36a806ca33cf94d901da022793a4da7b739bfb439400301b162fd84dcc92a307077fee7c34c75edd2457cf7a5bcb82b5dcd8aaf41b7959
'''



already_registered_keys = [(bytes.fromhex('1b619323d95a9bc9215ecc87c50d32f3f3c7ee01c0e45d04c4b612d6fa91367a4774d2184e6a053a2748fc67b33f9cf524ebc2a3aed28ff6a20569e908f4b107'),bytes.fromhex('04de612c5ee0982bdd4a36a806ca33cf94d901da022793a4da7b739bfb439400301b162fd84dcc92a307077fee7c34c75edd2457cf7a5bcb82b5dcd8aaf41b7959'),None)]
tid = bytes.fromhex('8d26eee6f0b1dcd2052963b6e809281bdd22871c76e881856299cd5dbaaf76b1')
request = generate_idassertion_request('https://jong.sh', tid, already_registered_keys)
print(request)

'''

{"signRequests":[{"appId":"https://jong.sh","challenge":"jSbu5vCx3NIFKWO26AkoG90ihxx26IGFYpnNXbqvdrEE3mEsXuCYK91KNqgGyjPPlNkB2gInk6Tae3Ob-0OUADAbFi_YTcySowcHf-58NMde3SRXz3pby4K13Niq9Bt5WQAAAAAA","keyHandle":"G2GTI9lam8khXsyHxQ0y8_PH7gHA5F0ExLYS1vqRNnpHdNIYTmoFOidI_GezP5z1JOvCo67Sj_aiBWnpCPSxBw","version":"U2F_V2"}],"type":"u2f_sign_request"}



p.postMessage({"signRequests":[{"appId":"https://jong.sh","challenge":"jSbu5vCx3NIFKWO26AkoG90ihxx26IGFYpnNXbqvdrEE3mEsXuCYK91KNqgGyjPPlNkB2gInk6Tae3Ob-0OUADAbFi_YTcySowcHf-58NMde3SRXz3pby4K13Niq9Bt5WQAAAAAA","keyHandle":"G2GTI9lam8khXsyHxQ0y8_PH7gHA5F0ExLYS1vqRNnpHdNIYTmoFOidI_GezP5z1JOvCo67Sj_aiBWnpCPSxBw","version":"U2F_V2"}],"type":"u2f_sign_request"})

>>>

{"keyHandle":"G2GTI9lam8khXsyHxQ0y8_PH7gHA5F0ExLYS1vqRNnpHdNIYTmoFOidI_GezP5z1JOvCo67Sj_aiBWnpCPSxBw","clientData":"eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZ2V0QXNzZXJ0aW9uIiwiY2hhbGxlbmdlIjoialNidTV2Q3gzTklGS1dPMjZBa29HOTBpaHh4MjZJR0ZZcG5OWGJxdmRyRUUzbUVzWHVDWUs5MUtOcWdHeWpQUGxOa0IyZ0luazZUYWUzT2ItME9VQURBYkZpX1lUY3lTb3djSGYtNThOTWRlM1NSWHozcGJ5NEsxM05pcTlCdDVXUUFBQUFBQSIsIm9yaWdpbiI6Imh0dHBzOi8vam9uZy5zaCIsImNpZF9wdWJrZXkiOiJ1bnVzZWQifQ","signatureData":"AQAAAAAwQwIfWQlWaaTBfjCunf59AA34L_Y19LWbPWGVe8hXkWLt-AIgRX_B4cyQFQx1sA0TRWzEzs8cmXMVQ7b8a0E75b-BEsI"}

'''

tid = bytes.fromhex('8d26eee6f0b1dcd2052963b6e809281bdd22871c76e881856299cd5dbaaf76b1')
response = '{"keyHandle":"G2GTI9lam8khXsyHxQ0y8_PH7gHA5F0ExLYS1vqRNnpHdNIYTmoFOidI_GezP5z1JOvCo67Sj_aiBWnpCPSxBw","clientData":"eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZ2V0QXNzZXJ0aW9uIiwiY2hhbGxlbmdlIjoialNidTV2Q3gzTklGS1dPMjZBa29HOTBpaHh4MjZJR0ZZcG5OWGJxdmRyRUUzbUVzWHVDWUs5MUtOcWdHeWpQUGxOa0IyZ0luazZUYWUzT2ItME9VQURBYkZpX1lUY3lTb3djSGYtNThOTWRlM1NSWHozcGJ5NEsxM05pcTlCdDVXUUFBQUFBQSIsIm9yaWdpbiI6Imh0dHBzOi8vam9uZy5zaCIsImNpZF9wdWJrZXkiOiJ1bnVzZWQifQ","signatureData":"AQAAAAAwQwIfWQlWaaTBfjCunf59AA34L_Y19LWbPWGVe8hXkWLt-AIgRX_B4cyQFQx1sA0TRWzEzs8cmXMVQ7b8a0E75b-BEsI"}'

facetid, kh, pk, cnt_old, cnt_new = process_idassertion_response('https://jong.sh', tid, response)
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
