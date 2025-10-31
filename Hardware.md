#iq-test
To find the output after a series of logicalm operators

##solution: 

First I immediately realised the need to convert the decimal to 36-digit binary as inputs to logic gates. I created a java program to find the binary and got `011100011000101001000100101010101110` as binary for `30478191278`. 
After finding the binary I computed the results through logic gates and after series of computations got the answer
java code for num to binary
```
public class DecimalToBinary {
    public static void main(String[] args) {
        // Use 'long' because the number is too big for 'int'.
        // Add an 'L' at the end to mark it as a long literal.
        long decimalNumber = 30478191278L;

        // Use the built-in method to convert the long to a binary string
        String binaryString = Long.toBinaryString(decimalNumber);

        System.out.println("Decimal: " + decimalNumber);
        System.out.println("Binary:  " + binaryString);
    }
}
```

##Flag
nite{100010011000}

##Learnings
I learnt the use of logic gates and how combinations of them can be used to create a complex circuit. Additionally I also found how to compute binary of long integers by a java program

##Notes
Initially I forgot to account for how long number is and by default used int.

##References
None

-------------------------------------------------------------------------------------------------------------------------

#Ilikelogic
The challenge provided a challenge.zip file containing a digital logic capture and a description file desc (1).txt which simply said "i like logic and i like files.

## Solution
The sal extention pointed to the Saleae Logic software. The "files" clue suggested a file-related protocol. I open itin the Saleae Logic 2 software.I saw that only Channel D3 had any signal activity.A single active line prompted me to use Async Serial (UART) transmission.I added an Async Serial analyzer from the Analyzers tab on the right and configured it to use Channel D3 as its `Serial` input with all the standard configurations

I finally got a long list of lines and content in between which was hidden our file

## Flag
`FCSC{b1dee4eeadf6c4e60aeb142b0b486344e64b12b40d1046de95c89ba5e23a9925}`

## Learnings
I learn what a sal file is and how to use logic2 software to decode it as well as how to choose the protocol. The number of active signal lines is a critical clue. A single active line strongly implies Async Serial.
This challenge required getting familiar with the Saleae Logic 2 interface, specifically how to add and configure an analyzer.

## Reference
https://www.manualslib.com/manual/1414020/Saleae-Logic.html

--------------------------------------------------------------------------------------------------------------------------

#Bare Metal Alchemist
To find flag from a file given

##Solution
Upon seeing the downloaded file with a weird .elf extention. I double clicked and opened it in notepad which had strange symbols appered. My instinct went to use string command in ubuntu terminal but that didn't work.Then I decided to use a hex editor to see the assembly code and take a hint but even that went in vain. I realised the programm isn't as simple and it might be transformed using XOR. I decided to create a python script and compare the resukt to pattern that looks like flag 

```python
import re

def find_flag(filepath, pattern):
    try:

        with open(filepath, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        print(f"Error: The file '{filepath}' was not found.")
        return

    for key in range(1, 256):

        xored_data = bytes([byte ^ key for byte in data])

        match = pattern.search(xored_data)

        if match:

            print(f"This key matches: {key}")
            print(f"Flag: {match.group().decode()}")

if __name__ == "__main__":

    FLAG_PATTERN = re.compile(rb"[A-Za-z0-9_]{1,30}\{[A-Za-z0-9_\-\+\=\/\\\.\s]{4,200}\}")
    FIRMWARE_FILE = "firmware.elf"

```

output:
```
ritesh@LAPTOP-9AUNFI81:~$ nano pythonS.py
ritesh@LAPTOP-9AUNFI81:~$ python3 pythonS.py
This key matches: 9
Flag: mfVjelh{VkzzVz}
This key matches: 11
Flag: T{ydlyjf
              TT}
This key matches: 19
Flag: LL{vrcLv}
This key matches: 24
Flag: GG{lwjkG}
This key matches: 26
Flag: lh5{lh/5vsx}
This key matches: 30
Flag: Aqh{lxrqiA}
This key matches: 46
Flag: ojc{v.ojm.ojm}
This key matches: 52
Flag: 4kkqqdf{ykfqs}
This key matches: 56
Flag: yt8{tshj8kj}
This key matches: 57
Flag: 9mnxtk9mn{k9mnzk9mnjk9mn}
This key matches: 66
Flag: HBB{vBALxIyI
                  Q}
This key matches: 68
Flag: W{HFNDD}
This key matches: 71
Flag: TxKEMGG{sGDI}
This key matches: 107
Flag: mzjyjhcpcNcxnkkkjzk{mzjyjhcpcNcxnkkk}
This key matches: 109
Flag: hmmm{mmmom}
This key matches: 118
Flag: vv{BvuxL}
This key matches: 121
Flag: yy{yyyyy}
This key matches: 122
Flag: zzzzzzzzxuzzz{rymzzzx}
This key matches: 165
Flag: TFCCTF{Th1s_1s_som3_s1mpl3_4rdu1no_f1rmw4re}
```
hence `TFCCTF{Th1s_1s_som3_s1mpl3_4rdu1no_f1rmw4re}` looks like flag.

##flag:
`TFCCTF{Th1s_1s_som3_s1mpl3_4rdu1no_f1rmw4re}`
##Learnings
I learnt that sometime not just reading the file helps us get flag but have to think outside the box to find hit.. The forensics task also hinted that file maybe transformed by XOR. Learnt how to create a python scipt similar to the said function.

##Notes
I wasted a lot of time intially using strings and then at hex editor to find clue of what must be done to file forgetting that it could be a transformation case

##References
https://www.geeksforgeeks.org/dsa/string-transformation-using-xor-and-or/
https://www.youtube.com/watch?v=h7Cgx-pn9bw

_____________________________________________________________________________  
