# 代码验证（Code validation）

在测试用例中，对被测逻辑（procedure/function等）进行验证，是通过将实际数据与预期数据进行比较来实现的。utPLSQL使用结合了期望和匹配器来对数据进行检查。

某些校验是用`ut.expect(actual_value).matcher(expected_value)`的形式编写的。这行规则检查`actual_value`和`expected_value`是否相同。示例：

```
...
begin
  v_expected := '2345';
  v_actual := betwnstr('1234567', 2, 5);
  ut.expect(v_actual).to_equal(v_actual); -- 这个期望是错误的，它总是正确的
end;

```