#### 实现流程

由两部分组成：
1. elf修改工具。
2. 重定位shellcode。

使用dlopen+dlsym获取需要重定位的函数的地址。
搜索`/system/lib/libdl.so`获取dlopen/dlsym地址。

