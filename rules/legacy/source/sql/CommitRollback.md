# 避免在数据库对象中调用COMMIT或ROLLBACK

通常，事务的控制权应由其所有者来处理。
如果事务是由某些Java代码开始的，那么它的提交和回滚应该在Java代码中进行。

因此，在这种情况下，从数据库对象中调用COMMIT或ROLLBACK是不好的实践，应避免这样做。

此规则忽略了具有`PRAGMA AUTONOMOUS_TRANSACTION`的存储过程和函数。