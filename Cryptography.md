# 1. Abuse the Oracle

We are given two encrypted files, `password (1).enc` and `secret (1).enc`. We are also provided with a remote oracle service that can encrypt or decrypt data. The oracle's one rule is that it will not decrypt the specific ciphertext found in `password (1).enc`. The goal is to find a way to get the plaintext of the password, and then use that password to decrypt the `secret (1).enc` file to find the flag.

## Solution:
First I listed the files and examined their contents: `password (1).enc` contained a very long integer and `secret (1).enc` was binary data. I then checked what oracle does and it encrypts and decrypts data as fed to it except the password (1).enc.My thought process was to abuse this oracle's rule: it will decrypt *anything* as long as it's not the exact, original ciphertext from `password (1).enc`.The goal was to get the password `P` (which is the key for `secret (1).enc`), which was encrypted as `C = Enc(P)`.

I can't ask the oracle to decrypt `Enc(P)`. But I can ask it to decrypt a different ciphertext, `C'`, where `C' = Enc(P) * Enc(2)`. The oracle will decrypt this to `Dec(C') = P * 2`.I wrote the following Python script using `pwntools` to perform this attack automatically:

    ```python
    from pwn import *

    conn = remote("titan.picoctf.net", 54779, level='debug')
    
    # Encrypt 2
    conn.recvuntil('E --> encrypt D --> decrypt.')
    conn.sendline('E')
    conn.recvline()
    conn.sendline("\x02")
    res = conn.recvuntil('E --> encrypt D --> decrypt.').decode('utf-8')
    two = int(res.split('\n')[4].split()[-1])
    
    # Decrypt encrypt(2)*pwd
    with open('password (1).enc','r') as f:
        pwd = int(f.read().strip())
    
    conn.sendline('D')
    conn.recvline()
    conn.sendline(str(two * pwd)) # This sends Enc(P * 2)
    res = conn.recvuntil('E --> encrypt D --> decrypt.').decode('utf-8')
    hex_value = res.split('\n')[0].split()[-1] # This gets the hex for P * 2
    
    # Divide the result by 2 to get decrypt(pwd)
    m2 = int(hex_value, 16)
    m2 //= 2
    pwd = bytes.fromhex(hex(m2)[2:]).decode('utf-8')
    print(pwd)
    ```

My script first connected, asked the oracle to encrypt `2`, and got back `Enc(2)`. Then it read `Enc(P)` from my local `password (1).enc` file. It multiplied them together and sent the result to the oracle for decryption. The oracle sent back the hex for `P * 2`. My script parsed this divided it by 2 and printed the final key: `881d9`.This key `881d9` was the password for the `secret (1).enc` file. I used `openssl` to decrypt it. My filename had spaces and parentheses, so I had to wrap it in single quotes.

    ```bash
    openssl enc -aes-256-cbc -d -in 'secret (1).enc' -k 881d9
    ```

This command printed the final flag.
```
ritesh@LAPTOP-9AUNFI81:~$ cat 'password (1).enc'

1765037049764047724348114634473658734830490852066061345686916365658618194981097216750929421734812911680434647401939068526285652985802740837961814227312100ritesh@LAPTOP-9AUNFI81:~$ cat 'secret (1).'secret (1).enc'

�Q���t*�$����Wqt�Qw����^Qritesh@LAPTOP-9AUNFI81:~$ nc titan.picoctf.net 54779

*****************************************

****************THE ORACLE***************

*****************************************

what should we do for you?

E --> encrypt D --> decrypt.

E

enter text to encrypt (encoded length must be less than keysize): 2

2



encoded cleartext as Hex m: 32



ciphertext (m ^ e mod n) 4707619883686427763240856106433203231481313994680729548861877810439954027216515481620077982254465432294427487895036699854948548980054737181231034760249505



what should we do for you?

E --> encrypt D --> decrypt.

D

Enter text to decrypt:  4707619883686427763240856106433203231481313994680729548861877810439954027216515481620077982254465432294427487895036699854948548980054737181231034760249505

decrypted ciphertext as hex (c ^ d mod n): 32

decrypted ciphertext: 2



what should we do for you?

E --> encrypt D --> decrypt.

^C

ritesh@LAPTOP-9AUNFI81:~$ nano rsa.py

ritesh@LAPTOP-9AUNFI81:~$ python3 rsa.py

[+] Opening connection to titan.picoctf.net on port 54779: Done

/home/ritesh/rsa.py:6: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes

  conn.recvuntil('E --> encrypt D --> decrypt.')

[DEBUG] Received 0xb8 bytes:

    b'*****************************************\n'

    b'****************THE ORACLE***************\n'

    b'*****************************************\n'

    b'what should we do for you? \n'

    b'E --> encrypt D --> decrypt. \n'

/home/ritesh/rsa.py:7: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes

  conn.sendline('E')

[DEBUG] Sent 0x2 bytes:

    b'E\n'

/home/ritesh/rsa.py:9: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes

  conn.sendline("\x02")

[DEBUG] Sent 0x2 bytes:

    00000000  02 0a                                               │··│

    00000002

/home/ritesh/rsa.py:10: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes

  res = conn.recvuntil('E --> encrypt D --> decrypt.').decode('utf-8')

[DEBUG] Received 0x42 bytes:

    b'enter text to encrypt (encoded length must be less than keysize): '

[DEBUG] Received 0x111 bytes:

    00000000  02 0a 0a 65  6e 63 6f 64  65 64 20 63  6c 65 61 72  │···e│ncod│ed c│lear│

    00000010  74 65 78 74  20 61 73 20  48 65 78 20  6d 3a 20 32  │text│ as │Hex │m: 2│

    00000020  0a 0a 63 69  70 68 65 72  74 65 78 74  20 28 6d 20  │··ci│pher│text│ (m │

    00000030  5e 20 65 20  6d 6f 64 20  6e 29 20 35  30 36 37 33  │^ e │mod │n) 5│0673│

    00000040  31 33 34 36  35 36 31 33  30 34 33 36  35 31 32 37  │1346│5613│0436│5127│

    00000050  35 34 32 39  36 36 35 33  31 35 38 39  35 38 32 34  │5429│6653│1589│5824│

    00000060  31 35 37 37  35 35 37 37  39 32 32 32  33 37 32 39  │1577│5577│9222│3729│

    00000070  37 39 34 34  36 30 37 36  30 31 32 33  35 36 33 32  │7944│6076│0123│5632│

    00000080  34 34 39 38  31 39 30 38  32 38 32 31  30 33 33 35  │4498│1908│2821│0335│

    00000090  37 36 33 39  37 39 33 33  30 32 37 32  33 31 38 36  │7639│7933│0272│3186│

    000000a0  35 37 32 36  39 30 34 38  34 33 35 33  31 31 38 39  │5726│9048│4353│1189│

    000000b0  37 38 39 36  34 33 33 37  32 31 31 31  35 36 30 36  │7896│4337│2111│5606│

    000000c0  37 36 34 34  34 32 31 39  39 34 39 37  38 39 31 32  │7644│4219│9497│8912│

    000000d0  31 39 32 33  30 0a 0a 77  68 61 74 20  73 68 6f 75  │1923│0··w│hat │shou│

    000000e0  6c 64 20 77  65 20 64 6f  20 66 6f 72  20 79 6f 75  │ld w│e do│ for│ you│

    000000f0  3f 20 0a 45  20 2d 2d 3e  20 65 6e 63  72 79 70 74  │? ·E│ -->│ enc│rypt│

    00000100  20 44 20 2d  2d 3e 20 64  65 63 72 79  70 74 2e 20  │ D -│-> d│ecry│pt. │

    00000110  0a                                                  │·│

    00000111

Traceback (most recent call last):

  File "/home/ritesh/rsa.py", line 14, in <module>

    with open('password.enc','r') as f:

         ^^^^^^^^^^^^^^^^^^^^^^^^

FileNotFoundError: [Errno 2] No such file or directory: 'password.enc'

[*] Closed connection to titan.picoctf.net port 54779

ritesh@LAPTOP-9AUNFI81:~$ nano rsa.py

ritesh@LAPTOP-9AUNFI81:~$ python3 rsa.py

[+] Opening connection to titan.picoctf.net on port 54779: Done

/home/ritesh/rsa.py:6: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes

  conn.recvuntil('E --> encrypt D --> decrypt.')

[DEBUG] Received 0xb8 bytes:

    b'*****************************************\n'

    b'****************THE ORACLE***************\n'

    b'*****************************************\n'

    b'what should we do for you? \n'

    b'E --> encrypt D --> decrypt. \n'

/home/ritesh/rsa.py:7: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes

  conn.sendline('E')

[DEBUG] Sent 0x2 bytes:

    b'E\n'

/home/ritesh/rsa.py:9: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes

  conn.sendline("\x02")

[DEBUG] Sent 0x2 bytes:

    00000000  02 0a                                               │··│

    00000002

/home/ritesh/rsa.py:10: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes

  res = conn.recvuntil('E --> encrypt D --> decrypt.').decode('utf-8')

[DEBUG] Received 0x42 bytes:

    b'enter text to encrypt (encoded length must be less than keysize): '

[DEBUG] Received 0x111 bytes:

    00000000  02 0a 0a 65  6e 63 6f 64  65 64 20 63  6c 65 61 72  │···e│ncod│ed c│lear│

    00000010  74 65 78 74  20 61 73 20  48 65 78 20  6d 3a 20 32  │text│ as │Hex │m: 2│

    00000020  0a 0a 63 69  70 68 65 72  74 65 78 74  20 28 6d 20  │··ci│pher│text│ (m │

    00000030  5e 20 65 20  6d 6f 64 20  6e 29 20 35  30 36 37 33  │^ e │mod │n) 5│0673│

    00000040  31 33 34 36  35 36 31 33  30 34 33 36  35 31 32 37  │1346│5613│0436│5127│

    00000050  35 34 32 39  36 36 35 33  31 35 38 39  35 38 32 34  │5429│6653│1589│5824│

    00000060  31 35 37 37  35 35 37 37  39 32 32 32  33 37 32 39  │1577│5577│9222│3729│

    00000070  37 39 34 34  36 30 37 36  30 31 32 33  35 36 33 32  │7944│6076│0123│5632│

    00000080  34 34 39 38  31 39 30 38  32 38 32 31  30 33 33 35  │4498│1908│2821│0335│

    00000090  37 36 33 39  37 39 33 33  30 32 37 32  33 31 38 36  │7639│7933│0272│3186│

    000000a0  35 37 32 36  39 30 34 38  34 33 35 33  31 31 38 39  │5726│9048│4353│1189│

    000000b0  37 38 39 36  34 33 33 37  32 31 31 31  35 36 30 36  │7896│4337│2111│5606│

    000000c0  37 36 34 34  34 32 31 39  39 34 39 37  38 39 31 32  │7644│4219│9497│8912│

    000000d0  31 39 32 33  30 0a 0a 77  68 61 74 20  73 68 6f 75  │1923│0··w│hat │shou│

    000000e0  6c 64 20 77  65 20 64 6f  20 66 6f 72  20 79 6f 75  │ld w│e do│ for│ you│

    000000f0  3f 20 0a 45  20 2d 2d 3e  20 65 6e 63  72 79 70 74  │? ·E│ -->│ enc│rypt│

    00000100  20 44 20 2d  2d 3e 20 64  65 63 72 79  70 74 2e 20  │ D -│-> d│ecry│pt. │

    00000110  0a                                                  │·│

    00000111

Traceback (most recent call last):

  File "/home/ritesh/rsa.py", line 14, in <module>

    with open('password(1).enc','r') as f:

         ^^^^^^^^^^^^^^^^^^^^^^^^^^^

FileNotFoundError: [Errno 2] No such file or directory: 'password(1).enc'

[*] Closed connection to titan.picoctf.net port 54779

ritesh@LAPTOP-9AUNFI81:~$ nano rsa.py

ritesh@LAPTOP-9AUNFI81:~$ python3 rsa.py

[+] Opening connection to titan.picoctf.net on port 54779: Done

/home/ritesh/rsa.py:6: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes

  conn.recvuntil('E --> encrypt D --> decrypt.')

[DEBUG] Received 0xb8 bytes:

    b'*****************************************\n'

    b'****************THE ORACLE***************\n'

    b'*****************************************\n'

    b'what should we do for you? \n'

    b'E --> encrypt D --> decrypt. \n'

/home/ritesh/rsa.py:7: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes

  conn.sendline('E')

[DEBUG] Sent 0x2 bytes:

    b'E\n'

/home/ritesh/rsa.py:9: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes

  conn.sendline("\x02")

[DEBUG] Sent 0x2 bytes:

    00000000  02 0a                                               │··│

    00000002

/home/ritesh/rsa.py:10: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes

  res = conn.recvuntil('E --> encrypt D --> decrypt.').decode('utf-8')

[DEBUG] Received 0x42 bytes:

    b'enter text to encrypt (encoded length must be less than keysize): '

[DEBUG] Received 0x111 bytes:

    00000000  02 0a 0a 65  6e 63 6f 64  65 64 20 63  6c 65 61 72  │···e│ncod│ed c│lear│

    00000010  74 65 78 74  20 61 73 20  48 65 78 20  6d 3a 20 32  │text│ as │Hex │m: 2│

    00000020  0a 0a 63 69  70 68 65 72  74 65 78 74  20 28 6d 20  │··ci│pher│text│ (m │

    00000030  5e 20 65 20  6d 6f 64 20  6e 29 20 35  30 36 37 33  │^ e │mod │n) 5│0673│

    00000040  31 33 34 36  35 36 31 33  30 34 33 36  35 31 32 37  │1346│5613│0436│5127│

    00000050  35 34 32 39  36 36 35 33  31 35 38 39  35 38 32 34  │5429│6653│1589│5824│

    00000060  31 35 37 37  35 35 37 37  39 32 32 32  33 37 32 39  │1577│5577│9222│3729│

    00000070  37 39 34 34  36 30 37 36  30 31 32 33  35 36 33 32  │7944│6076│0123│5632│

    00000080  34 34 39 38  31 39 30 38  32 38 32 31  30 33 33 35  │4498│1908│2821│0335│

    00000090  37 36 33 39  37 39 33 33  30 32 37 32  33 31 38 36  │7639│7933│0272│3186│

    000000a0  35 37 32 36  39 30 34 38  34 33 35 33  31 31 38 39  │5726│9048│4353│1189│

    000000b0  37 38 39 36  34 33 33 37  32 31 31 31  35 36 30 36  │7896│4337│2111│5606│

    000000c0  37 36 34 34  34 32 31 39  39 34 39 37  38 39 31 32  │7644│4219│9497│8912│

    000000d0  31 39 32 33  30 0a 0a 77  68 61 74 20  73 68 6f 75  │1923│0··w│hat │shou│

    000000e0  6c 64 20 77  65 20 64 6f  20 66 6f 72  20 79 6f 75  │ld w│e do│ for│ you│

    000000f0  3f 20 0a 45  20 2d 2d 3e  20 65 6e 63  72 79 70 74  │? ·E│ -->│ enc│rypt│

    00000100  20 44 20 2d  2d 3e 20 64  65 63 72 79  70 74 2e 20  │ D -│-> d│ecry│pt. │

    00000110  0a                                                  │·│

    00000111

/home/ritesh/rsa.py:17: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes

  conn.sendline('D')

[DEBUG] Sent 0x2 bytes:

    b'D\n'

/home/ritesh/rsa.py:19: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes

  conn.sendline(str(two * pwd))

[DEBUG] Sent 0x134 bytes:

    b'8943996009575278864115573703991201712571074215117036179086668593808926390701605353776642251720073674504199260815309943536447818516632375817246532671301018861809177830861805075153232349532481616132684137546455678578211809237269343473990373627305672839436403271663643913293883535204677067137127081834731683000\n'

/home/ritesh/rsa.py:20: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes

  res = conn.recvuntil('E --> encrypt D --> decrypt.').decode('utf-8')

[DEBUG] Received 0x17 bytes:

    b'Enter text to decrypt: '

[DEBUG] Received 0x8e bytes:

    00000000  64 65 63 72  79 70 74 65  64 20 63 69  70 68 65 72  │decr│ypte│d ci│pher│

    00000010  74 65 78 74  20 61 73 20  68 65 78 20  28 63 20 5e  │text│ as │hex │(c ^│

    00000020  20 64 20 6d  6f 64 20 6e  29 3a 20 37  30 37 30 36  │ d m│od n│): 7│0706│

    00000030  32 63 38 37  32 0a 64 65  63 72 79 70  74 65 64 20  │2c87│2·de│cryp│ted │

    00000040  63 69 70 68  65 72 74 65  78 74 3a 20  70 70 62 c3  │ciph│erte│xt: │ppb·│

    00000050  88 72 0a 0a  77 68 61 74  20 73 68 6f  75 6c 64 20  │·r··│what│ sho│uld │

    00000060  77 65 20 64  6f 20 66 6f  72 20 79 6f  75 3f 20 0a  │we d│o fo│r yo│u? ·│

    00000070  45 20 2d 2d  3e 20 65 6e  63 72 79 70  74 20 44 20  │E --│> en│cryp│t D │

    00000080  2d 2d 3e 20  64 65 63 72  79 70 74 2e  20 0a        │--> │decr│ypt.│ ·│

    0000008e

881d9

[*] Closed connection to titan.picoctf.net port 54779

ritesh@LAPTOP-9AUNFI81:~$ openssl enc -aes-256-cbc -d -in secret.enc -k 881d9

Can't open "secret.enc" for reading, No such file or directory

4047946B8C720000:error:80000002:system library:BIO_new_file:No such file or directory:../crypto/bio/bss_file.c:67:calling fopen(secret.enc, rb)

4047946B8C720000:error:10000080:BIO routines:BIO_new_file:no such file:../crypto/bio/bss_file.c:75:

ritesh@LAPTOP-9AUNFI81:~$ openssl enc -aes-256-cbc -d -in secret (1).enc -k 881d9

-bash: syntax error near unexpected token `('

ritesh@LAPTOP-9AUNFI81:~$  openssl enc -aes-256-cbc -d -in 'secret (1).enc' -k 881d9

*** WARNING : deprecated key derivation used.

Using -iter or -pbkdf2 would be better.

picoCTF{su((3ss_(r@ck1ng_r3@_881d93b6}ritesh@LAPTOP-9AUNFI81:~$
```
## Flag:
picoCTF{su((3ss_(r@ck1ng_r3@_881d93b6}

## Concepts learnt:

The core concept that `Enc(A) * Enc(B) = Enc(A * B)` allows an attacker to "blind" a ciphertext and trick an oracle into decrypting it.Abusing an oracle by sending it specially crafted (chosen) data to decrypt.Also learned how to create a python snippet and run it in WSL terminal so as to get our desired cypertext sent to server and get the key and how to use `openssl enc` to decrypt an AES-CBC encrypted file using a derived key (`-k` flag).

## Notes:

My script initially failed with a `FileNotFoundError` because I had to manually edit the filename from `password.enc` to `password (1).enc` to match my local file No such file or directory: 'password.enc', FileNotFoundError: [Errno 2] No such file or directory: 'password(1).enc'].

## Resources:

https://ctf101.org/cryptography/overview/
https://people.csail.mit.edu/rivest/Rsapaper.pdf
https://blog.cbarkr.com/ctf/picoCTF/practice/rsa_oracle


---------------------------------------------------------------------
# 2. Custom Encryption

Can you get sense of this code file and write the function that will decode the given encrypted file content. Find the encrypted file here `enc_flag (1)` and `custom_encryption (1).py` code file might be good to analyze and get the flag.

## Solution:

The challenge requires us to reverse-engineer a custom Python encryption script to decrypt a given flag.
First, I analyzed the provided encryption script to understand how it works. It's composed of three main parts that are applied in layers:

1.  The `generator(g, x, p)` function and the `test()` function set up a standard Diffie-Hellman key exchange. They use hardcoded prime numbers `p = 97` and `g = 31`. The script generates two private keys, `a` and `b` and then computes a `shared_key`. This `shared_key` is the first key we need to recover.

2.  `dynamic_xor_encrypt`: This function is applied first. It takes the plaintext flag and a hardcoded `text_key` ("trudeau"). Crucially it reverses the plaintext using `plaintext[::-1]` and then performs a repeating-key XOR with "trudeau".

3.  `encrypt`: This function is applied second. It takes the output from the XOR and iterates over each character. It calculates the final cipher number using a formula.

To decrypt, we must reverse these steps in the opposite order.

The other file gives us the static values that were used for the encryption, bypassing the `randint` function in the original script. I created a new script `decrypt.py` to reverse the encryption process.

```python
def generator(g, x, p):
  return pow(g, x) % p

def decrypt(cipher, key):
  decrypted_text = ""
  for number in cipher:
      decrypted_num = number // (key * 311)
      decrypted_text += chr(decrypted_num)
  return decrypted_text

def dynamic_xor_decrypt(ciphertext, text_key):
  decrypted_text = ""
  key_length = len(text_key)
  for i, char in enumerate(ciphertext):
    key_char = text_key[i % key_length]
    decrypted_char = chr(ord(char) ^ ord(key_char))
    decrypted_text += decrypted_char
  return decrypted_text

# Values from the challenge files
p = 97
g = 31
a = 90
b = 26
cipher = [61578, 109472, 437888, 6842, 0, 20526, 129998, 526834, 478940, 287364, 0, 567886, 143682, 34210, 465256, 0, 150524, 588412, 6842, 424204, 164208, 184734, 41052, 41052, 116314, 41052, 177892, 348942, 218944, 335258, 177892, 47894, 82104, 116314]

# Step 1: Re-calculate the shared key
u = generator(g, a, p)
v = generator(g, b, p)
shared_key = generator(v, a, p)

# Step 2: Reverse the multiplication cipher
ciphertext = decrypt(cipher, shared_key)

# Step 3: Reverse the XOR cipher
print(dynamic_xor_decrypt(ciphertext, "trudeau"))
```

WSL terminal:
```
ritesh@LAPTOP-9AUNFI81:~$ cat custom_encryption.py
from random import randint
import sys


def generator(g, x, p):
    return pow(g, x) % p


def encrypt(plaintext, key):
    cipher = []
    for char in plaintext:
        cipher.append(((ord(char) * key*311)))
    return cipher


def is_prime(p):
    v = 0
    for i in range(2, p + 1):
        if p % i == 0:
            v = v + 1
    if v > 1:
        return False
    else:
        return True


def dynamic_xor_encrypt(plaintext, text_key):
    cipher_text = ""
    key_length = len(text_key)
    for i, char in enumerate(plaintext[::-1]):
        key_char = text_key[i % key_length]
        encrypted_char = chr(ord(char) ^ ord(key_char))
        cipher_text += encrypted_char
    return cipher_text


def test(plain_text, text_key):
    p = 97
    g = 31
    if not is_prime(p) and not is_prime(g):
        print("Enter prime numbers")
        return
    a = randint(p-10, p)
    b = randint(g-10, g)
    print(f"a = {a}")
    print(f"b = {b}")
    u = generator(g, a, p)
    v = generator(g, b, p)
    key = generator(v, a, p)
    b_key = generator(u, b, p)
    shared_key = None
    if key == b_key:
        shared_key = key
    else:
        print("Invalid key")
        return
    semi_cipher = dynamic_xor_encrypt(plain_text, text_key)
    cipher = encrypt(semi_cipher, shared_key)
    print(f'cipher is: {cipher}')


if __name__ == "__main__":
    message = sys.argv[1]
    test(message, "trudeau")
ritesh@LAPTOP-9AUNFI81:~$ nano decrypt.py
ritesh@LAPTOP-9AUNFI81:~$ python3 decrypt.py
}b5eebf94_d6tp0rc2d_motsuc{FTCocip
ritesh@LAPTOP-9AUNFI81:~$  nano decrypt.py
ritesh@LAPTOP-9AUNFI81:~$ python3 decrypt.py | rev
picoCTF{custom_d2cr0pt6d_49fbee5b}
```
Running the script as-is produced the reversed flag because the original script reversed the flag before encrypting it.o get the correct flag I piped the output of the script to the rev command which reverses the final string.

##Flag:
picoCTF{custom_2cr0pt6d_49feeb5}

##Concepts learnt:
Diffie-Hellman Key Exchange is a method for two parties to establish a shared secret key over an insecure channel. They agree on a prime and a generator.This challenge was a good example of a multi-layer cipher. To decrypt, you must reverse the layers in the opposite order they were applied (Last-In, First-Out).It's reversed by XORing the ciphertext with the same key.

##Notes:
My mistake was not noticing the plaintext[::-1] in the dynamic_xor_encrypt function, which leads to the flag being printed in reverse.

##Resources
https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange
https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher


------------------------------------------------------------------------

# miniRSA

To decrypt this ciphertext.

## Solution:

We are given a ciphertext file containing three values: a large modulus `N`, a public exponent `e`, and a ciphertext `c`.The challenge description hints that "Something seems a bit small." Looking at the data, the public exponent `e` is `3`, which is a very small value for `e`.This points directly to a "Small Public Exponent Attack".
The core of RSA encryption is the formula:C = M^e (mod N).This attack works on the assumption that the original message M was small enough that M^e is actually less than N.If M^e < N, the modular N part of the formula has no effect, and the equation simplifies to:C = M^e.To decrypt the message, we just need to calculate the e-th root of the ciphertext C. Since e=3, we are just calculating the cube root.

M = \sqrt[e]{C} or M = \sqrt[3]{C}

We need a special math library in Python, `gmpy2`, which is designed to handle large integers.The key function is `gmpy2.iroot(c, e)`, which efficiently calculates the integer e-th root of `c`.I created the following script `solve.py` to perform this attack:

```python
import gmpy2
import sys

# Values from the ciphertext file
n_str = "29331922499794985782735976045591164936683059380558950386560160105740343201513369939006307531165922708949619162698623675349030430859547825708994708321803705309459438099340427770580064400911431856656901982789948285309956111848686906152664473350940486507451771223435835260168971210087470894448460745593956840586530527915802541450092946574694809584880896601317519794442862977471129319781313161842056501715040555964011899589002863730868679527184420789010551475067862907739054966183120621407246398518098981106431219207697870293412176440482900183550467375190239898455201170831410460483829448603477361305838743852756938687673"
e_str = "3"
cipher_str = "2205316413931134031074603746928247799030155221252519872650080519263755075355825243327515211479747536697517688468095325517209911688684309894900992899707504087647575997847717180766377832435022794675332132906451858990782325436498952049751141"

# Convert to gmpy2 large integers (mpz)
c = gmpy2.mpz(cipher_str)
n = gmpy2.mpz(n_str)
e = gmpy2.mpz(e_str)

# Calculate the integer e-th root
# This is the "Small Public Exponent Attack"
# m = c^(1/e)
m, exact = gmpy2.iroot(c, e)

if exact:
    print(f"[*] Found exact {e}-th root!")
    
    # Convert the integer message 'm' into a hex string
    hex_string = format(m, 'x')
    
    # Add padding if hex string is odd length (bytes.fromhex needs even)
    if len(hex_string) % 2 != 0:
        hex_string = '0' + hex_string
        
    # Convert the hex string into raw bytes
    flag_bytes = bytes.fromhex(hex_string)
    
    # Decode the bytes into a readable string
    try:
        flag = flag_bytes.decode('utf-8')
        print(f"[*] Flag: {flag}")
    except UnicodeDecodeError:
        print(f"[*] Could not decode bytes as utf-8. Raw bytes: {flag_bytes}")
else:
    print("[-] Could not find an exact root. The attack failed.")

```

This final string is the flag.

WSL Terminal 
```
ritesh@LAPTOP-9AUNFI81:~$ sudo apt install python3-gmpy2
[sudo] password for ritesh:
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following additional packages will be installed:
  python-gmpy2-common
Suggested packages:
  python-gmpy2-doc
The following NEW packages will be installed:
  python-gmpy2-common python3-gmpy2
0 upgraded, 2 newly installed, 0 to remove and 31 not upgraded.
Need to get 205 kB of archives.
After this operation, 737 kB of additional disk space will be used.
Do you want to continue? [Y/n] Y
Get:1 http://archive.ubuntu.com/ubuntu noble/universe amd64 python-gmpy2-common all 2.1.5-3build1 [27.2 kB]
Get:2 http://archive.ubuntu.com/ubuntu noble/universe amd64 python3-gmpy2 amd64 2.1.5-3build1 [178 kB]
Fetched 205 kB in 1s (137 kB/s)
Selecting previously unselected package python-gmpy2-common.
(Reading database ... 58169 files and directories currently installed.)
Preparing to unpack .../python-gmpy2-common_2.1.5-3build1_all.deb ...
Unpacking python-gmpy2-common (2.1.5-3build1) ...
Selecting previously unselected package python3-gmpy2.
Preparing to unpack .../python3-gmpy2_2.1.5-3build1_amd64.deb ...
Unpacking python3-gmpy2 (2.1.5-3build1) ...
Setting up python-gmpy2-common (2.1.5-3build1) ...
Setting up python3-gmpy2 (2.1.5-3build1) ...
Processing triggers for man-db (2.12.0-4build2) ...
ritesh@LAPTOP-9AUNFI81:~$ python3 solve.py
[*] Found exact 3-th root!
[*] Flag: picoCTF{n33d_a_lArg3r_e_d0cd6eae}
```
##Flag:
picoCTF{th3_c4rd_w45_A_sp4d35_48107871}

##Concepts learnt:
The basic encryption function is C = M^e (mod N). Small Public Exponent Attack ia a specific attack on RSA that works when the exponent e is small (like 3) and the message M is also small enough that M^e < N. In this case, the decryption simplifies to M = sqrt[e]{C}.
I also learnt that gmpy2 Library is anessential Python library for cryptography that provides functions for high-precision arbitrary-precision arithmetic. The gmpy2.iroot(c, e) function was key to this challenge.Python Data Conversion: This challenge required converting between data types:gmpy2.mpz(): To convert a string to a large integer.format(m, 'x'): To convert an integer to a hex string.bytes.fromhex(): To convert a hex string to a bytes object..decode('utf-8'): To convert a bytes object to a readable string.

##Notes
None

##References
https://ctf101.org/cryptography/overview/
https://people.csail.mit.edu/rivest/Rsapaper.pdf

-------------------------------------------------------------------------
