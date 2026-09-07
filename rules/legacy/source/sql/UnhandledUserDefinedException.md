# 未处理的异常

当在代码中声明了一个自定义异常但没有处理时，抛出这个异常将在数据库中引发错误 "ORA-06510: PL/SQL: unhandled user-defined exception"，或在 Oracle Forms 中显示为 "用户定义异常"。

这是处理自定义异常的好习惯。

不合规代码示例
---------------

```

DECLARE
  my_exception EXCEPTION;
BEGIN
  ...
  RAISE my_exception; -- 这将导致一个“用户定义异常”
END;

```

合规解决方案
--------------

```

DECLARE
  my_exception EXCEPTION;
BEGIN
  ...
  RAISE my_exception;
EXCEPTION
  WHEN my_exception THEN
    ...
END;

```

此检查还将触发违规，如果异常由 OTHERS 处理器处理且引用到 SQLERRM。在这种情况下，SQLERRM 将返回 "用户定义异常"，这并不是很有用。

```

DECLARE
  my_exception EXCEPTION;
BEGIN
  ...
  RAISE my_exception;
EXCEPTION
  WHEN OTHERS THEN
    log(SQLERRM);
END;

```