# 题目：跳转语句（`return`, `exit`, `continue`, 和 `raise`）会脱离当前代码块控制流程。

## 漏洞描述

跳转语句（`return`, `exit`, `continue`, 和 `raise`）会脱离当前代码块控制流程。通常，任何在块后面出现的语句都是等待着让不谨慎的人感到困惑的无用字符串。

## 非合规代码示例

```sql
begin
  raise my_error;
  log('finished'); -- 这段代码将永远不会被执行
end;
```

## 合规解决方案

```sql
begin
  raise my_error;
end;
```