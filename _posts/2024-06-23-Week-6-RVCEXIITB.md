---
layout: post
title: "The Summer of Challs: Week 6"
date: 2024-06-23
categories: CTFs
---

This week, I solved some easy web challenges from the RVCExIITB CTF. 

## ROBOT UPRISING

We open the website to see this: 

![Robot Uprising](/assets/RobotUprising.jpg)

Based on the name of the challenge and the fact that there isn't much here, I decided to check the robots.txt file, where I saw this: 

![Robot Uprising](/assets/RURobots.jpg)

From this, I reasoned that I needed to change the user-agent to WALL-E. I did this and got the flag:

![Robot Uprising](/assets/RUFlag.jpg)

## Confidential Leak

This just seems like a simple site with a login form: 

![Confidential Leak](/assets/ConfidentiaLeak.jpg)

When you hit submit, a POST request is made to the `/login` endpoint of the website. Whatever I submit however, is obviously going to be incorrect, and the message "Username is Wrong" is returned. 

I used some basic directory fuzzing with Gobuster to find out that a `/script` endpoint was leaked:

```Javascript
var express = require('express');
var app = express();
var port = process.env.PORT || 9898;
var crypto = require('crypto');
var bodyParser = require('body-parser')
var salt = 'somestring';
var iteration = /// some number here;
var keylength = // some number here;

app.post('/login', function (req, res) {
    var username = req.body.username;
    var password = req.body.password;
    if (username !== 'joemama') {
        res.send('Username is wrong');
        return;
    }
    if (crypto.pbkdf2Sync(password, salt, iteration, keylength).toString() === hashOfPassword) {
        if (password === 'plnlrtfpijpuhqylxbgqiiyipieyxvfsavzgxbbcfusqkozwpngsyejqlmjsytrmd') {
            // some logic here and return something
        } else {
            // return flag here
        }
    } else {
        res.send('Password is wrong');
    }
});


if (username !== 'joemama') {
        res.send('Username is wrong');
        return;
    }
```

From this, I figured out the username: "joemama". We can also see that the method `crypto.pbkdf2Sync` is being used on whatever password we input, and comparing it to a hash of the original password. The javascript then checks if the password is equal to the string `plnlrtfpijpuhqylxbgqiiyipieyxvfsavzgxbbcfusqkozwpngsyejqlmjsytrmd` - if it isn't, we get the flag. 

To summarize the flow here, we have to enter a string that results in the hash of the original password, and that string can't be `plnlrtfpijpuhqylxbgqiiyipieyxvfsavzgxbbcfusqkozwpngsyejqlmjsytrmd`.

It seems we need to do something called a hash collision, where the hashing algorithm used can actually return identical hashes for two different strings. This is because it seems to be denying the actual password. In other words, we need to provide a false password that passes both the hashing check and second password check. Luckily for us, someone found a collision with crypto.pbkdf2Sync: [Collisions Blog Post](https://mathiasbynens.be/notes/pbkdf2-hmac). 

They actually used the exact same string, `plnlrtfpijpuhqylxbgqiiyipieyxvfsavzgxbbcfusqkozwpngsyejqlmjsytrmd`, and found that there is a hash collision with the string `eBkXQTfuBqp'cTcar&g*`. I submitted the username `joemama` and the password `eBkXQTfuBqp'cTcar&g*"` and got the flag:

![Confidential Leak](/assets/ConfidentialLeakFlag.jpg)

## Hiring

This was the best challenge of the bunch, and included something that we haven't seen on the blog yet. 

We are told to upload our resume to this form: 

![Hiring](/assets/Hiring.jpg)

The challenge post tells us that the name of the resume we upload will be hashed with its checksum, and uploaded with a more secure name. When we submit the file, a POST request is made to the `/upload.php` endpoint of the website. 

This SCREAMS file upload vulnerability, specifically with PHP. This usually means we have to somehow upload a PHP file, because PHP servers will just execute them as code instead of simply rendering their content. Out of curiosity, I uploaded a .PNG file in the resume field, and this was returned: 

![Hiring](/assets/HiringError.jpg)

From this, we can tell that there is some sanitization of file types, and they are using the `md5_file()` function to hash our upload. 

When I uploaded a pdf file to the resume field, found its MD5 File Checksum with this tool, ([MD5 Checksum Calculator](https://emn178.github.io/online-tools/md5_checksum.html)), and went to `url/uploads/hash.pdf`, I was able to see my upload. 

In order to get a potential flag, we need to figure out a way to bypass the file type sanitization and upload a php script. Hacktricks had a nice technique for this [Hacktricks File Bypass](https://book.hacktricks.xyz/pentesting-web/file-upload).

What worked for me was uploading a file named something like `test.pdf.php`. The server was misconfigured to see it as a pdf file (even though it was a php script) and it passed the check. I first tried with this:

```PHP
<?php echo "hello world"; ?>
```

I found the hash, went to the `/uploads` endpoint, and sure enough:

![Hiring](/assets/HiringFUVProof.jpg)

The server executed our code! I then toyed with the `shell_exec()` function and uploaded various payloads to try and see where we were in the server. Eventually, I formed the working payload `<?php echo shell_exec('cat ../../../../flag.txt'); ?>` and was able to get the flag:

![Hiring](/assets/HiringFlag.jpg)

While most of these challenges were more lightweight, they still are helping me increase my volume of experience - I'm feeling slow but sure progress.  Next week I will try to do some more rev and continue the web grind. 
