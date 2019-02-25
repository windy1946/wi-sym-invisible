# 符号表隐藏

## 项目结构组成
1. elf-tool，用于对so文件做修改，包括符号抹去，数据修改（将被抹去的符号传递给stub）。
2. stub，存放shellcode，用于对so中被抹去的符号做重定位。

## elf-tool
- 将需要隐藏的符号的符号表(`Elf64_Sym`)，重定位表(`Elf64_Rela`)，符号名称(`symbol name`)这三个数据结构类型传递给stub。
- 将需要抹去的符号对应的重定位表移到所有的重定位表的末尾，再将重定位表的数量减1。
- 将需需要抹去的符号对应的符号表中数据置0，即实现符号抹去。


## stub
- 由于stub中的shellcode是被attach到新的so上的，所以用到的所有导入符号都需要自己去获取其地址(stub/jni/utils.c中)。
- 使用到的dlopen，dlsym，mprotect分别在linker.so、linker.so、libc.so中，通过搜索maps文件获取其对应的so加载地址，再通过符号表计算得到其绝对地址。
- 各个平台对应的syscall则需要自己实现。


