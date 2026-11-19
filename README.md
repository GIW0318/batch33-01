# GSB Bugfix Task
## 题面
开放平台给第三方发 API key 后，权限开始收不住：read:* 匹配不到 read:users，write:user 反而能匹配 write:users；过期 key 还能用；注销只改本地缓存，服务端照样放行；重复 key id 直接覆盖旧 scope。api_key_scope.py 的 ApiKeyStore 负责 issue、authorize 和 revoke。实现要支持精确 scope 和通配匹配，过期和注销立即失效，重复 id 和非法 scope 报错，未知 key 拒绝；authorize 只返回布尔值，不能改状态。 第三方会按环境拿不同的 key，测试 key 不能访问生产资源；scope 通配只能向后匹配一层，不能把 read:users 扩大成整个 read 域。

## 运行方式
```bash
python -m pytest tests -q
```

## 平台字段

所属领域：安全
子方向：身份认证
任务类型：Bugfix
语言 / 框架：Python 3, pytest
环境可复现等级：有外部依赖，未容器化
