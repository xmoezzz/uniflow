# SQL源码漏洞描述

## 1.漏洞原理

在比较操作符中使用null值时，需要使用IS NULL和IS NOT NULL这两个特殊条件进行测试，因为其他任何与null值进行的比较都会返回NULL结果。此外，空字符串被视为null值。

## 2.非合规代码示例

非合规代码中使用了直接判断变量是否为null的方式，这种做法是不安全的，因为它可能无法检测到某些特定的null值情况。

- 示例一（使用IS NOT NULL）：
  ```sql
  if var = null then
    -- code
  end if;
  ```

- 示例二（使用IS ''）：
  ```sql
  if other_var = '' then
    -- code
  end if;
  ```

## 3.合规解决方案

为了确保安全，应该使用IS NULL和IS NOT NULL这两个特殊条件来测试变量是否为null。

- 示例一（使用IS NULL）：
  ```sql
  if var is null then
    -- code
  end if;
  ```

- 示例二（使用IS NOT NULL）：
  ```sql
  if other_var is not null then
    -- code
  end if;
  ```