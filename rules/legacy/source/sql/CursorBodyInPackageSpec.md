# 漏洞名称：SQL注入漏洞

## 漏洞描述：

在Oracle Forms中，游标声明可以分为两部分：声明和体。当在一个包规范中声明一个游标时，包规范应该只包含游标声明，而游标体应添加到包体中。

## 非合规代码示例：

```sql
CREATE OR REPLACE PACKAGE pkg IS
  CURSOR cur IS
    SELECT DUMMY FROM Dual;
END;
```

## 合规解决方案：

```sql
CREATE OR REPLACE PACKAGE pkg IS
  TYPE cur_type IS RECORD(dummy VARCHAR2(1));
  CURSOR cur RETURN cur_type;
END;
/
CREATE OR REPLACE PACKAGE BODY pkg IS
  CURSOR cur RETURN cur_type IS
    SELECT DUMMY FROM Dual;
END;
/
```