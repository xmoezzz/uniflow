# SQL中使用`TO_CHAR`函数的错误

在SQL中，如果在`ORDER BY`子句中使用`TO_CHAR`函数，那么它可能会导致列 values 的顺序与其实际数据类型不一致。通常情况下，这会使得列按照字符串顺序排序，而不是按其实际数据类型排序。

## 不合规代码示例

假设我们有一个名为`EMP`的表，其中包含以下数据：

| empno | hiredate |
| ------ | ---------- |
| 1       | 2019-10-01 |
| 5       | 2019-10-10 |
| 15      | 2018-10-02 |
| 20     | 2018-10-20 |

下面是一些不合规的查询，返回了不想看到的结果：

1. `select empno from emp order by to_char(empno);`

| empno |
|-------|
| 1     |
| 15    |
| 20    |
| 5     |

2. `select hiredate from emp order by to_char(hiredate, 'dd-mm-rrrr');`

| hiredate |
|-------|
| 01-OCT-19 |
| 02-OCT-18 |
| 10-OCT-19 |
| 20-OCT-18 |

## 合规代码示例

为了正确地排序这些列，我们必须去掉`TO_CHAR`调用。

1. `select empno from emp order by empno;`

| empno |
|-------|
| 1     |
| 5     |
| 15    |
| 20    |

2. `select hiredate from emp order by hiredate;`

| hiredate |
|-------|
| 02-OCT-18 |
| 20-OCT-18 |
| 01-OCT-19 |
| 10-OCT-19 |