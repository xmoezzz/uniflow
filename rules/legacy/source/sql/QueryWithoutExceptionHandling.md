## SQL 查询异常处理漏洞（Bypassing Application-Defined Limits）

在编写SQL查询时，我们通常应该添加一个异常处理块，以避免意外的异常情况。如果没有进行适当的异常处理，某些类型的SQL查询可能会导致“ SQLiteNoSurfaceException”。这个异常是由SQLite数据库库生成的，当查询超出了数据库能够处理的范围时，会抛出这个异常。攻击者可以利用这个漏洞绕过应用程序定义的限制，执行不受限制的SQL语句。

为了防止这种情况发生，开发人员应该确保在所有SELECT语句之前添加一个`try`-`except`块，以捕获和处理可能发生的任何异常。