#Trivial Flag Transfer Protocol

Figure out how they moved the flag.

##Solution
looking at the packet capture using Wireshark I noticed there were a lot of files. To extract them I went to File > Export Objects > TFTP which shows all the files recorded in the packet capture.The files included instructions.txt, plan, program.deb, picture1.bmp, picture2.bmp, and picture3.bmp. Let's analyze each of them individually.

instructions.txt
Here are the contents of instructions.txt:
```
GSGCQBRFAGRAPELCGBHEGENSSVPFBJRZHFGQVFTHVFRBHESYNTGENAFSRE.SVTHERBHGNJNLGBUVQRGURSYNTNAQVJVYYPURPXONPXSBEGURCYNA
```
An Encrypted data. My first thought was a substitution of some sort and it turned out to be ROT13
```
TFTPDOESNTENCRYPTOURTRAFFICSOWEMUSTDISGUISEOURFLAGTRANSFER.FIGUREOUTAWAYTOHIDETHEFLAGANDIWILLCHECKBACKFORTHEPLAN
```

plan
Here are the raw contents of plan:
```
VHFRQGURCEBTENZNAQUVQVGJVGU-QHRQVYVTRAPR.PURPXBHGGURCUBGBF
```
Once again it is encrypted using ROT13. Here's the decrypted message
```
IUSEDTHEPROGRAMANDHIDITWITH-DUEDILIGENCE.CHECKOUTTHEPHOTOS
```

program.deb
I opened program using 7-zip and found many pictures, Theactual content of the pictures themselves have absolutely nothing to do with anything..There's a part on steghide's README titled "Quick-Start" that explains how to use it. I used the command steghide info picture3.bmp and it prompted me for a passcode.I remembered the contents of plan:

IUSEDTHEPROGRAMANDHIDITWITH-DUEDILIGENCE.CHECKOUTTHEPHOTOS
ANDHIDITWITH-DUEDILIGENCE

and realsied "DUEDILIGENCE" was the password the flag is hidden.Using steghide extract -sf picture3.bmp and "DUEDILIGENCE" as the password, flag.txt was extracted.
![Picture1](\\wsl.localhost\Ubuntu\home\ritesh\picoCTF\foreinsicstftp)
![Picture2](\\wsl.localhost\Ubuntu\home\ritesh\picoCTF\foreinsicstftp>
![Picture3](\\wsl.localhost\Ubuntu\home\ritesh\picoCTF\foreinsicstftp)
##Flag
picoCTF{h1dd3n_1n_pLa1n_51GHT_18375919}

##Learnings
I learn to use thw wireshark software and how it can be used to analyse network traffic and how swiftly information can be hidden in packets tha we had to discover. I also learnt ti usr steghide extract function.
##Notes
Initially I opted out pictures as random data until I read readme and got to know its use

##References:
https://www.spiceworks.com/it-articles/what-is-tftp/
Gemini AI (for downloading wireshark and learn how to use it)

-----------------------------------------------------------------------

#tunn3l v1s10n
To recover a flag from the file

##Solution
There is a problem opening the file. Running file tunn3l_v1s10n produces tunn3l_v1s10n: data, which is not helpful. We use a hex editor and see if there is a match between the magic bytes. We can see the first bytes as

```
┌──(user@kali)-[/media/sf_CTFs/pico/tunn3l_v1s10n]
└─$ xxd -g 1 tunn3l_v1s10n | head
00000000: 42 4d 8e 26 2c 00 00 00 00 00 ba d0 00 00 ba d0  BM.&,...........
00000010: 00 00 6e 04 00 00 32 01 00 00 01 00 18 00 00 00  ..n...2.........
00000020: 00 00 58 26 2c 00 25 16 00 00 25 16 00 00 00 00  ..X&,.%...%.....
00000030: 00 00 00 00 00 00 23 1a 17 27 1e 1b 29 20 1d 2a  ......#..'..) .*
00000040: 21 1e 26 1d 1a 31 28 25 35 2c 29 33 2a 27 38 2f  !.&..1(%5,)3*'8/
00000050: 2c 2f 26 23 33 2a 26 2d 24 20 3b 32 2e 32 29 25  ,/&#3*&-$ ;2.2)%
00000060: 30 27 23 33 2a 26 38 2c 28 36 2b 27 39 2d 2b 2f  0'#3*&8,(6+'9-+/
00000070: 26 23 1d 12 0e 23 17 11 29 16 0e 55 3d 31 97 76  &#...#..)..U=1.v
00000080: 66 8b 66 52 99 6d 56 9e 70 58 9e 6f 54 9c 6f 54  f.fR.mV.pX.oT.oT
00000090: ab 7e 63 ba 8c 6d bd 8a 69 c8 97 71 c1 93 71 c1  .~c..m..i..q..q.

```
It actually starts with BM, so this might be a BMP file. And indeed, if we change the extension to BMP and open it, we get an image together with some text saying "notaflag{sorry}".
The size of the image is 1134x306 but on thorough analysis the file itself is larger than it should be
We changed the height of the bitmap using the hex editor . The width starts at hex offset 12, lasts for 4 bytes, and is followed by the height at offset 16, which is also 4 bytes.We make the change in the hex editor replacing 32 01 at offset 16 to 6e 04, save the image.

![image](\\wsl.localhost\Ubuntu\home\ritesh\picoCTF\forensictunnel)

##Flag:
picoCTF{qu1t3_a_v13w_2020}

##Learnings
I learnt how to use a hex editor and from data table we can change the corrupted file to its right type. I also learnt to change the height to extend the image and obtain the flag

##Notes
None

##References

https://en.wikipedia.org/wiki/List_of_file_signatures
https://en.wikipedia.org/wiki/BMP_file_format
https://www.youtube.com/watch?v=giv0DQDSsjQ

----------------------------------------------------------------------
#m00nwalk
To decode the message from the moon.

##Solution

Nothing meaningdul was there in file to listen nor visualising helped. SSTV seamed a viable option considering even the challenge's name moonwalk relates how images of moon landing were transmitted back on earth.Via trial and error I figured out the Qsstc's mode as Scottie 1. And played to start Found the image with flag on it

```root@kali:/media/sf_CTFs/pico/m00nwalk# paplay -d virtual-cable message.wav```

![m00nwalk](\\wsl.localhost\Ubuntu\home\ritesh\picoCTF\foreinsicstftp)

##Flag
picoCTF{beep_boop_im_in_space}

##Learnings
I learnt various ways to decode an audio file. I learnt what sstv is Slow Scan television (SSTV) is a picture transmission method used mainly by amateur radio operators, to transmit and receive static pictures via radio in monochrome or color. The Apollo TV cameras used SSTV to transmit images from inside Apollo 7, Apollo 8, and Apollo 9, as well as the Apollo 11 Lunar Module television from the Moon. I learn the qssr command in terminal and its use as well.

##Notes
None

##References
https://ourcodeworld.com/articles/read/956/how-to-convert-decode-a-slow-scan-television-transmissions-sstv-audio-file-to-images-using-qsstv-in-ubuntu-18-04

----------------------------------------------------------------------
