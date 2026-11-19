# GSB Bugfix Task
## 题面
图片上传接进移动端后，解码线程开始被大图拖死：宽高相乘超过预算的 PNG 仍然进入解码；动图帧数没有上限，一帧一帧解到内存爆；WebP 声明尺寸很小但字节数异常大；格式伪装成 JPEG 的 ZIP 也能过；EXIF 里的缩略图和外链没有剥离。media_decode_guard.py 的 MediaDecodeGuard 负责 inspect。实现要校验格式白名单、宽高和像素总量、字节数、动图帧数、压缩比，剥离外链和缩略图元数据，返回规范化后的尺寸和字节；负数、非整数和未知格式抛 ValueError。

## 运行方式
```bash
python -m pytest tests -q
```

## 平台字段

所属领域：安全
子方向：系统安全
任务类型：Bugfix
语言 / 框架：Python 3, pytest
环境可复现等级：有外部依赖，未容器化
