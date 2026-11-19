# GSB Bugfix Task
## 题面
模板渲染接入多语言后台后，同一个昵称放进 HTML 正文、属性值、内联脚本、CSS 和链接里都只做一种转义：双引号和反斜杠能闭合字符串，</script> 直接截断脚本块，URL 里的空格和引号没有编码。template_escape.py 的 TemplateEscaper 负责 escape。实现要按 html、attr、js、css、url 五种上下文分别处理 &、尖括号、引号、反斜杠、换行和 </script>，控制字符拒绝；未知上下文和非法输入报错。 同一个模板会在服务端预渲染和客户端水合两处执行，转义规则必须一致；URL 上下文要区分路径、查询参数和片段，不能只做一次整体编码。

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
