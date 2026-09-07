# 题目：带有OUT参数的功能难以理解

## 漏洞描述

在函数中使用OUT参数使得情况变得复杂，因为无法仅通过查看函数调用来确定参数是输入还是输出。此外，具有OUT参数的功能不能从SQL中调用。

## 不合规代码示例

以下是一个不合规的代码示例：

```sql
CREATE OR REPLACE FUNCTION get_product_info(id IN NUMBER, value OUT NUMBER) RETURN VARCHAR2 IS
BEGIN
    -- 在这里进行一些操作...
    RETURN '返回值';
END;
```