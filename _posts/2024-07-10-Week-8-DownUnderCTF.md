---
layout: post
title: "The Summer of Challs: Week 7"
date: 2024-06-23
categories: CTFs
---

This week, I worked on the Down Under CTF. It was pretty big with a variety of challenges, both in topic and difficulty. Here is a very basic XXE injection one that I managed to solve:


## ZOO FEEDBACK FORM

We are given a basic form to submit some text:

![Zoo Feedback](/assets/ZooFeedback.jpg)

I used the chrome dev tools to see what happens when we submit some text (I submitted "hello"), and saw this in the network tab:

![Zoo Feedback](/assets/ZooFeedbackPayload.jpg)

A POST request is made to the root endpoint with this XML payload:

```XML
<?xml version="1.0" encoding="UTF-8"?>
            <root>
                <feedback>hello</feedback>
            </root>
```

To sum up what is happening, the front end takes our input, puts it in the `feedback` element of an XML payload, and then sends it to the backend. This is supposedly where the "emus" read our message.

Extensible Markup Language (XML) is a markup language where you can define your own tags and entities. It is a way for data to be transferred, stored, and transmitted. Usually, some kind of library/platform API is used server side to parse the XML data.

XML payloads can be modified in certain ways to pass these parsers, and manipulate the server. When the payloads are not sanitized and proper protection is not provided, applications that use XML can be vulnerable to XML external entity (XXE) injections.

We were provided with most of the server side code, and I didn't find any attempt at santizing the XML data coming in. 

Therefore, the application is certainly vulnerable to an XXE injection.

In order to write this exploit, we need to define an external entity that references the `flag.txt` file inside of the server. Within the code provided by the challenge, the path to this was `/app/flag.txt`.

To make the external entity, we have to use a `DOCTYPE` element, because XML allows  entities to be defined inside of them. To make the entity external, we need to declare it with the `SYSTEM` keyword and make it reference something outside of the element - in this case, we can do this with the `file://` protocol. The resrouce we are accessing is `flag.txt`, which exists outside of the `DOCTYPE` element that we have defined our atribute in. To call it, we simply do `&nameOfEntity` inside the feedback element. 

Here is the full payload I wrote:
```XML
<?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///app/flag.txt">]>
  <root>
   <feedback>
      &xxe;
   </feedback>
   </root>
```

I submitted this and got the flag:

![Zoo Feedback](/assets/ZooFeedbackFlag.jpg)

Not too difficult, but something new to put up here. Hopefully, I will be able to complete a larger number of challenges for next week, but this was a cool CTF with some very interesting topics. 
