# SQL中的条件重复漏洞

在SQL中，一条链式的`if`/`elsif`语句会从上到下进行评估。至多只能执行一个分支：第一个满足条件的分支。
因此，重复的条件会导致代码死亡。这通常是由于复制粘贴错误引起的。
至多，它仅仅是死亡代码，至少，它可能是一个会在维护代码时引发更多错误的bug，显然，它可能会导致预期行为。

非合规代码示例
--------------

```sql
IF (param = 1) THEN
  open();
ELSIF (param = 2) THEN
  close();
ELSIF (param = 1) THEN // 不正确
  move();
END IF;
```

合规解决方案
----------

```sql
IF (param = 1) THEN
  open();
ELSIF (param = 2) THEN
  close();
ELSIF (param = 3) THEN
  move();
END IF;
```