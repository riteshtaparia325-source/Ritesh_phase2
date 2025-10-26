# Reverse Engineering Writeups

---

## Challenge: GDB Baby step 1
To figure out  what is in the `eax` register at the end of the `main` function

### Solution
My goal was to find the value in the `eax` register. I understood I needed a debugger like GDB to access code and get the value.
1.  I cd'ed to the directory where I knew the file was stored
2.  Changed it's mod to executable just for ensuring that it executed
1.  I loaded the file into GDB and allowed it be debugged
2.  Set the assembly syntax to Intel, as it's easier to read.
3.  Disassemble the `main` function to see the code.
4.  Look at the end of the function, right before the `ret` instruction, for a `mov eax, ...` command.
5.  This command showed the final value being placed in the register.
6.  Converted that value from hexadecimal to decimal.

```
ritesh@LAPTOP-9AUNFI81:~$ cd /mnt/c/Users/Asus/Downloads
ritesh@LAPTOP-9AUNFI81:/mnt/c/Users/Asus/Downloads$ chmod +x debugger0_a
ritesh@LAPTOP-9AUNFI81:/mnt/c/Users/Asus/Downloads$ gdb ./debugger0_a

This GDB supports auto-downloading debuginfo from the following URLs:
  <https://debuginfod.ubuntu.com>
Enable debuginfod for this session? (y or [n]) y
Debuginfod has been enabled.
To make this setting permanent, add 'set debuginfod enabled on' to .gdbinit.
Downloading separate debug info for /mnt/c/Users/Asus/Downloads/debugger0_a
(No debugging symbols found in ./debugger0_a)
(gdb) set disassembly-flavor intel
(gdb) disassemble main
Dump of assembler code for function main:
   0x0000000000001129 <+0>:     endbr64
   0x000000000000112d <+4>:     push   rbp
   0x000000000000112e <+5>:     mov    rbp,rsp
   0x0000000000001131 <+8>:     mov    DWORD PTR [rbp-0x4],edi
   0x0000000000001134 <+11>:    mov    QWORD PTR [rbp-0x10],rsi
   0x0000000000001138 <+15>:    mov    eax,0x86342
   0x000000000000113d <+20>:    pop    rbp
   0x000000000000113e <+21>:    ret
End of assembler dump.
(gdb)
```
###Flag
picoCTF{549698}

### New Concepts Learned
1. GDB: How to use `gdb` to load a program.
2. GDB Commands:**
    * `set disassembly-flavor intel`: Command to make assembly readable.
    * `disassemble main`: This command targets a specific function and prints its assembly code.
Assembly commands
    * The `eax` register is used to store the return value of a function.
    * The `mov` instruction moves a value into a register.
    * The `ret` instruction ends a function.

Overall I learnt the basics of reverse engineering, how to decode the assembly code in our favour and to understand what that code intends to do.

###Notes: 
None

### Resources:
*https://www.youtube.com/watch?v=gh2RXE9BIN8
*https://www.youtube.com/watch?v=1d-6Hv1c39c
*https://youtu.be/QOPOeDPlNZo
*https://youtu.be/YyovCxsMVio
Gemini AI: Used to know how to access the file in windows usingcd /mnt/c/Users/Asus/Downloads
Also to install and learn the GDB and its commands
-----------------------------------------------------------------

## ARMssembly 1

To find for what argument does this program print `win` with 68,2 and 3.

## Solution:

My thought process was to analyze the provided assembly source file to understand its logic. Since it's a source file (`.S`), I can just read the code directly without needing a debugger.

1.  I first looked at the `main` function to see how the program decides to print "win".
    After analysing I realised it calls the function to get a return value w0 and compares it with 0. If not equal it prints lose message, so I understood I needed to analyse the function to see when it returns w0=0.


2. Since main converts our command line input into integer saves it and invoke the function with our argument, it was time to analyse what make that function return 0 when our argument is passed.

3.  I traced `func` step-by-step to see what it calculates. 

      * The function intially saves 68,2 and 3 at specific locations
        ``` assembly
        ldr    w0, [sp, 20]  ; loads w0 = 2
        ldr    w1, [sp, 16]  ; w1 = 68
        lsl    w0, w1, w0    ; shift w1 by 2 bits to left,w0= 272
        ```
      * As we saw lsl instruction was used for Logical Shift Left by 2 bits here thats converts w0=272 (68*4= 272)
        ``` assembly
        ldr    w1, [sp, 28]  ; w1 = 272 (from previous result)
        ldr    w0, [sp, 24]  ; w0 = 3
        sdiv   w0, w1, w0    ; w0 = w1 / w0 = (272 / 3) = 90 (integer division)
        ```
      * As we can see now sdiv operation was used which reduced w0=90(272/3=90)

      * Then our passed argument is made to subtract from this number w0= 90, and passed value it returned at end of function
 
4.   The function returns `90 - our arument`,and we know this value must be 0 since we analysed main and this was condition to win, so the argument becomes 90.

5.  Now we convert it to hexadecimal and make a 32-bit (8 hex digit) format which results `0000005a`

```
ritesh@LAPTOP-9AUNFI81:/mnt/c/Users/Asus/Downloads$ cat chall_1.S
        .arch armv8-a
        .file   "chall_1.c"
        .text
        .align  2
        .global func
        .type   func, %function
func:
        sub     sp, sp, #32
        str     w0, [sp, 12]
        mov     w0, 68
        str     w0, [sp, 16]
        mov     w0, 2
        str     w0, [sp, 20]
        mov     w0, 3
        str     w0, [sp, 24]
        ldr     w0, [sp, 20]
        ldr     w1, [sp, 16]
        lsl     w0, w1, w0
        str     w0, [sp, 28]
        ldr     w1, [sp, 28]
        ldr     w0, [sp, 24]
        sdiv    w0, w1, w0
        str     w0, [sp, 28]
        ldr     w1, [sp, 28]
        ldr     w0, [sp, 12]
        sub     w0, w1, w0
        str     w0, [sp, 28]
        ldr     w0, [sp, 28]
        add     sp, sp, 32
        ret
        .size   func, .-func
        .section        .rodata
        .align  3
.LC0:
        .string "You win!"
        .align  3
.LC1:
        .string "You Lose :("
        .text
        .align  2
        .global main
        .type   main, %function
main:
        stp     x29, x30, [sp, -48]!
        add     x29, sp, 0
        str     w0, [x29, 28]
        str     x1, [x29, 16]
        ldr     x0, [x29, 16]
        add     x0, x0, 8
        ldr     x0, [x0]
        bl      atoi
        str     w0, [x29, 44]
        ldr     w0, [x29, 44]
        bl      func
        cmp     w0, 0
        bne     .L4
        adrp    x0, .LC0
        add     x0, x0, :lo12:.LC0
        bl      puts
        b       .L6
.L4:
        adrp    x0, .LC1
        add     x0, x0, :lo12:.LC1
        bl      puts
.L6:
        nop
        ldp     x29, x30, [sp], 48
        ret
        .size   main, .-main
        .ident  "GCC: (Ubuntu/Linaro 7.5.0-3ubuntu1~18.04) 7.5.0"
        .section        .note.GNU-stack,"",@progbits
```

## Flag:
picoCTF{0000005a}

## Concepts learnt:

-   Learnt about some instructions like
    -   `lsl`: Logical Shift Left- this shifts the binary number to `x` bit as provided along the argument  
    -   `sdiv`: Does division.
    -   `sub`: Does subtraction
    -   `mov`:To mave a value to register 
    -   `str`: Saves a register's value to a memory location
    -   `ldr`: Loads a value from a memory location into a register.
    -   `adrp`: To load full address of label in register
    -   `bl`: To call function
    -   `cmp`: compare equality
   


## Notes:

-   I initially assumed that variables 68, 2, and 3" from the description passed as arguments but in reality they were hardcoded directly inside the `func` function. The *only* argument passed was our input.

## Resources:

-   https://cseweb.ucsd.edu/classes/fa15/cse30/lectures/lec8_detailed.pdf
-   https://www.youtube.com/watch?v=s38DcLv1wYk
---------------------------------------------------------------------------------------------------------------------------------

# 3. Vault door 3

To analyse the given java code and reach the right ans.

## Solution:

My thought process was to cat the The file which lead to a java code .I had already learnt java so analysing it was easy. I understood the trickery was in for loop  where the password was broken and certain segments were scrambled in between and finally the scrambled string was revealed to us "jU5t_a_sna_3lpm12g94c_u_4_m7ra41"

1.  Loop 1: Standard indexing is done and hence no change in first 8 characters (i=0 to i=7).

2.  Loop 2: In this form i=8 to i=15, the indexing is reversed and hence we get a reversed output  

  
3.  Loop 3: In this the even indexes from i=16 to i=30 is taken and reversed again.

4.  Loop 4: The odd positions are now filled in the standard way and hence is same as the original string 

Now I rearrange the flag for loop 2 and 3 reversed it and upon re arranging get the correct flag.
```
ritesh@LAPTOP-9AUNFI81:/mnt/c/Users/Asus/Downloads$ cat VaultDoor3.java
import java.util.*;

class VaultDoor3 {
    public static void main(String args[]) {
        VaultDoor3 vaultDoor = new VaultDoor3();
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter vault password: ");
        String userInput = scanner.next();
        String input = userInput.substring("picoCTF{".length(),userInput.length()-1);
        if (vaultDoor.checkPassword(input)) {
            System.out.println("Access granted.");
        } else {
            System.out.println("Access denied!");
        }
    }

    // Our security monitoring team has noticed some intrusions on some of the
    // less secure doors. Dr. Evil has asked me specifically to build a stronger
    // vault door to protect his Doomsday plans. I just *know* this door will
    // keep all of those nosy agents out of our business. Mwa ha!
    //
    // -Minion #2671
    public boolean checkPassword(String password) {
        if (password.length() != 32) {
            return false;
        }
        char[] buffer = new char[32];
        int i;
        for (i=0; i<8; i++) {
            buffer[i] = password.charAt(i);
        }
        for (; i<16; i++) {
            buffer[i] = password.charAt(23-i);
        }
        for (; i<32; i+=2) {
            buffer[i] = password.charAt(46-i);
        }
        for (i=31; i>=17; i-=2) {
            buffer[i] = password.charAt(i);
        }
        String s = new String(buffer);
        return s.equals("jU5t_a_sna_3lpm12g94c_u_4_m7ra41");
    }
}
```
## Flag:
picoCTF{jU5t_a_s1mpl3_an4gr4m_4_u_c79a21}

## Concepts learnt:

-   Learnt how to read a Java program to understand its logic and act accordingly to reach the correct flag
## Notes:

None

## Resources:

None

***
