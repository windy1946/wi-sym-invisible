# 符号表隐藏

## 项目结构组成
1. elf-tool，用于对so文件做修改，包括符号抹去，数据修改（将被抹去的符号传递给stub）。
2. stub，存放shellcode，用于对so中被抹去的符号做重定位。
3. test，测试样例，使用elf-tool对test中so做修改。通过执行`./build.sh`完成测试。

## elf-tool
- 将需要隐藏的符号的符号表(`Elf64_Sym`)，重定位表(`Elf64_Rela`)，符号名称(`symbol name`)这三个数据结构类型传递给stub。
- 将需要抹去的符号对应的重定位表移到所有的重定位表的末尾，再将重定位表的数量减1。
- 将需需要抹去的符号对应的符号表中数据置0，即实现符号抹去。


## stub
- 由于stub中的shellcode是被attach到新的so上的，所以用到的所有导入符号都需要自己去获取其地址(stub/jni/utils.c中)。
- 使用到的dlopen，dlsym，mprotect分别在linker.so、linker.so、libc.so中，通过搜索maps文件获取其对应的so加载地址，再通过符号表计算得到其绝对地址。
- 各个平台对应的syscall则需要自己实现。


## stub patch
将stub patch到目标（target）so有两种种不同的方式分别为：
- a.在目标so中插入一段能够占据一定空间，但无用的代码，使其编译后能够有足够的空间存放stub。
```c
__volatile__ __aligned(0x1000) stub(){
    asm ("\t.space 8192\n");
};
```

- b.将stub以一个新LOAD段的形式patch到目标so中，即在目标so中插入多一个具备`WX`属性的`LOAD`段，并将`stub`放到其中。

## 执行stub
为了能够让`stub`在so被加载的时候先执行，实现对符号做重定位，需要将`so`的`init`地址指向该`stub`中，并使得`stub`执行完跳回`so`原本的`init`。（即init hook）
流程：

1. 获取`stub`中入口函数在`stub`所在`so`的偏移(`read_elf()`)，记为`sb_offset`;
2. 获取`target`中要将`stub` `patch`上去的位置，记为`tg_offset`。
3. 获取`target`中`init`的偏移：记为`init_offset`。
4. 计算将`stub` `patch`到`target`后`read_elf()`与原`init`之间的偏移`offset`，其中`offset=sb_offset+tg_offset - init_offset`(如果`init_offset`为0，则`offset=0`);
5. 将`stub`中的`magic（offset_to_init_data）`修改为`offset`的值。