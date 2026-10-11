# Hongguo Standalone Signer

目标：把海外 `libmetasec_ml.so` 直接仿真进 iOS，App 不再依赖电脑后端。

## 已确认

- iOS 侧只需要 4 个头：`X-Gorgon`、`X-Argus`、`X-Ladon`、`X-Khronos`。
- 实测删掉 `X-Helios`、`X-Medusa` 后，`multi_video_detail` 和 `multi_video_model` 仍然正常。
- 公开纯算法实现对应旧版/国内 `0404` Gorgon，海外 signer 返回的是 `8404` 变体，不能直接复用。
- `unicorn-engine-tci` 是无 JIT 的 Unicorn 分支，可避免 iOS 可执行内存限制。

## Unidbg 实际调用面

用 `TraceFq` 跑海外有效测试向量后，JNI 高层调用只有：

```text
com/bytedance/mobsec/metasec/ml/MS->b(IIJLjava/lang/String;Ljava/lang/Object;)Ljava/lang/Object;
java/lang/String->getBytes(Ljava/lang/String;)[B
```

实际 syscall 集合（去掉 Unidbg 内部中断号）：

```text
48, 56, 57, 63, 80, 98, 113, 167, 172, 178, 214, 215, 220, 222, 226
```

有效海外测试向量：

```text
URL: https://api5-normal-sinfonlinec.fqnovel.com/reading/bookapi/search/tab/v?aid=1967&device_id=4223674528607515&iid=4223674528611611&version_code=68132&query=test
Header: x-ss-req-ticket\r\n1754299673613\r\ncontent-type\r\napplication/json
```

该向量返回了完整签名，X-Gorgon 形如：

```text
840400a20000fba46e1fadfd448c58d11822fefa2d2188a498a7
```

## 当前骨架

已经实现：

- `libmetasec_ml.so` 的 AArch64 ELF 解析
- Unicorn TCI 内存映射：代码段、栈、堆、JNIEnv 表
- `MS.b` JNI op 映射
- Linux AArch64 常见 syscall 编号表
- C ABI：`hongguo_sign` / `hongguo_free_string`

还没实现：

- AArch64 `svc` syscall 分发
- 假 `JNIEnv` 函数表
- `JNI_OnLoad` 执行
- `SO + 0x168c80` 签名入口执行
- 返回值解析成 `X-*` headers

## 下一步

1. 按 Unidbg/`FqTrace` 的 JNI 行为实现 `JNIEnv` 表。
2. 实现 `openat/read/close/fstat/gettimeofday/clock_gettime/mmap/mprotect`。
3. 调用 `SO + 0x58b80` 完成 `JNI_OnLoad`。
4. 调用 `SO + 0x168c80`，传 URL/headers，读取返回字符串。
5. 用现有 `127.0.0.1:54733/sign` 做 oracle 对比。
6. 交叉编译 `aarch64-apple-ios`，链接进 iOS App。

## 资源

iOS App 需要随包带：

```text
capture/fq_oversea/libmetasec_ml.so
capture/fq_oversea/libc++_shared.so
capture/fq_oversea/ms_16777218.bin
```

## 许可证

`unicorn-engine-tci` 是 GPL-2.0。若静态链接进分发的 App，需要评估 GPL 合规。`libmetasec_ml.so` 是 ByteDance 代码，实际分发前也要确认你的授权范围。
