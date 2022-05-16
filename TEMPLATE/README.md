## 使用说明

```shell
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release	# Release mode
cmake .. -DCMAKE_BUILD_TYPE=Debug	# Debug mode
make
```

- 根据自己的需要修改`CMakeLists.txt`或者在`src/`中添加子项目
- 选项`-DCMAKE_BUILD_TYPE`控制编译模式
- 对应平台的第三方依赖库放到`lib/win`, `lib/mac`, `lib/linux`相应目录
- 对应的头文件放到`include/`文件夹下
- 二进制文件/库文件 都生成在`out`文件夹下