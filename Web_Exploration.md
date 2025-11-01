# 1. SSTI1
To create a payload enough to give me flag using SSTI vulnerability to advantage

## Solution:

My thought process was to first test for a SSTI vulnerability as hinted by the challenge description.I first sent the payload {{ 4* 4 }}. The server responded with `16` instead of the literal string to confirm the suspiciosn.

 My goal was to read the flag file. I needed to "break out" of the template sandbox to run shell commands. I used a standard payload to access the os module:
    ```
    {{ config.__class__.__init__.__globals__['os'].popen('ls').read() }}
    ```
    
   This command worked and returned the file list: `__pycache__ app.py flag requirements.txt` which confirmed the flag file is named `flag`. I then modified the payload to cat the file and got the flag
```{{ config.__class__.__init__.__globals__['os'].popen('cat flag').read() }}```
    
    
This payload successfully returned the flag.

## Flag:

picoCTF{s4rv3r_s1d3_t3mp14t3_1nj3ct10n5_4r3_c001_9451989d}

## Concepts learnt:

  Server-Side Template Injection (SSTI) is the vulnerability that occurs when user-supplied input is rendered directly into a server-side template, allowing the user to execute code.This challenge was about escaping that sandbox and use the vulnerability to run our specific code payload.
  
  Learnt how to create a payload and what to feed to get our desired result

## Notes:

  - My initial attempts failed because I was trying to read `flag.txt` but the `ls` command revealed the file was just called `flag`.
  
## References:

 https://youtu.be/AtfNT0PFzZ4?si=3CliJwhWPKo_PHyL
 
 Gemini AI (for understanding payload)

-------------------------------------------------------------------------------------------------------------------------------------------

# 2. Cookies

To figure out the cookie value to give me the flag

## Solution:

My thought process was to investigate the "cookies" mentioned in the hint.

I inspected the page  found cookie Value `-1`. The page text said "I love different type of cookies!".This hinted to me to try different value.I decided to try a "hit and trial" approach and changed to different values till I got the flag at value=18.

## Flag:
picoCTF{3v3ry1_l0v3s_c00k135_064663be}

*(Note: I'm including the flag from your screenshot, which you found while testing value `18`)*

## Concepts learnt:

Cookies are Small pieces of data that websites store in our browser to keep track of information or "state". We can inspect the page and manipulate them to our advantage
   
## Notes:
   This manual process was slow but worked. A much faster, automated way to find the correct number would be to use a command-line script which I learnt later
:
    ```bash
    for i in $(seq 1 30); do curl -s --cookie "name=$i" [http://mercury.picoctf.net:27177/](http://mercury.picoctf.net:27177/)| grep "picoCTF{"; done
    ```

## Resources:

I had already done a similar challenge in citadel CTF before so was aware how to do it.

Gemini AI (for faster method than my hit and trial)

--------------------------------------------------------------------------------------------------------------------------------------------------------------

#3. Web Gauntlet 
To beat the filters

##Solution

Intially solving a similiar challenge i knew I had to somehow bypass banned words and give the alternate to bypass using sql injection. I didn't knew password but I knew the common sql injection `admin' --` to comment out  the password. 
Now  that commenting option is blocked I used another common `admin' /*` to bypass it as it is comments and conveys to take evrything from first part and nothing from second ignoring password.
the same bypass can be used for round 3. Now I had to refer some resources for understanding more bypasses.Since admin is block I understood had to use some kind of concatenation.
`ad'||'min'/*`- to bypass both round 4 and 5. `||` concats admin while `/*` takes care of commenting part.

##FLag:
picoCTF{y0u_m4d3_1t_a8b2e1c97d4f0a631e8c9b7d5f2a4g0h}

##Learnings: 
I learnt what sql injection is all about and idfferent ways to bypass it.
I also learnt commands like `admin' --`, `admin' /*` , `ad'||'min'/*` their purpose and how they could had been used alternatives to crack the password

##Notes
none

## References
https://portswigger.net/web-security/sql-injection/cheat-sheet

-----------------------------------------------------------------------------
