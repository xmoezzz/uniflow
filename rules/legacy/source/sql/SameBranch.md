# 重复代码漏洞

在相同的 `if` 结构中拥有两个具有相同实现分支是最小的工作重复，最大可能是编码错误。如果对于两个实例确实需要相同的逻辑，则它们应该被合并。

## 非合规代码示例

```sql
IF var BETWEEN 0 AND 10 THEN
  do_the_thing();
ELSIF var BETWEEN 10 AND 20 THEN
  do_the_thing(); -- 不合规; 重复了第一个条件
ELSIF var BETWEEN 20 AND 50 THEN
  do_the_another_thing();
ELSE
  do_the_rest()
END IF;
```

## 合规解决方案

```sql
IF var BETWEEN 0 AND 10 THEN
  do_the_thing();
ELSIF var BETWEEN 10 AND 20 THEN
  do_the_second_thing();
ELSIF var BETWEEN 20 AND 50 THEN
  do_the_another_thing();
ELSE
  do_the_rest();
END IF;
```