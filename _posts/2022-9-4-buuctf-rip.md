先查看一下开了哪些保护\
![image](https://user-images.githubusercontent.com/98165037/188303228-82ab9753-9b76-4bd4-85d5-21e54f7f9e3c.png)\
几乎没开什么保护\
放进ida看看\
![image](https://user-images.githubusercontent.com/98165037/188303300-b7aac343-6559-44c2-a808-26ac8cb60769.png)\
看到gets函数，一个明显的溢出点\
然后又发现了一个fun函数（后门函数？）可以直接get shell\
![image](https://user-images.githubusercontent.com/98165037/188303382-39a84a3f-4873-4b52-b3a2-683fe27772f3.png)\
所以就是通过gets函数溢出覆盖到rbp然后ret到fun函数地址去执行\
这里看到fun函数地址是0x401186\
![image](https://user-images.githubusercontent.com/98165037/188303687-0c2d3d55-c6ac-41c4-be4e-c723a63eb1b3.png)\
或者直接ret到0x40118A执行system("/bin/sh")\
双击s看到s距离rbp 15个字节，并且rbp有8字节，所以一共要覆盖（0xf+0x8）字节的长度\
![image](https://user-images.githubusercontent.com/98165037/188303576-db6e46ea-c60f-41cb-a0b9-ca36655ed1a8.png)\
所以exp如下\
![image](https://user-images.githubusercontent.com/98165037/188303611-7c8e565a-d00c-4aa7-83e9-8324a495c9d7.png)
