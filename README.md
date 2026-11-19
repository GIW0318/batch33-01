# GSB Bugfix Task
## 题面
客服后台的站内导航支持 target 参数，用户登录后会被带到 target 指定的页面。安全测试发现 target 可以写成 //evil、反斜杠、%2f%2f、带账号密码的地址、javascript: 或 data:，回车换行还能改响应头。return_path_guard.py 的 ReturnPathGuard 负责 settle。实现只接受单个斜杠开头的站内路径，以及配置里列出的完整站点；任何以两个斜杠开头、带反斜杠、含控制字符、带账号密码、使用脚本或数据伪协议的地址都拒绝；先解码再判断，非法目标抛 ValueError。 回跳地址会经过网关、前端路由和移动端深链三层，任何一层都不能把站内路径解释成站外地址；失败时要回到固定首页，不能使用请求里的地址。

## 运行方式
```bash
python -m pytest tests -q
```

## 平台字段

所属领域：安全
子方向：漏洞检测与攻防
任务类型：Bugfix
语言 / 框架：Python 3, pytest
环境可复现等级：有外部依赖，未容器化
