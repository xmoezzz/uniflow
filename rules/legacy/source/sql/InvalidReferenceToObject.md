# SQL代码漏洞概述

在Oracle Forms中，许多过程和函数需要引用一个对象（块，项目，警告等）。不幸的是，唯一的传递对象引用的方法是使用VARCHAR2变量，并且这些引用不会被编译器检查。

目前，此规则检查以下方法：

- 警告构建器：
    * FIND\_ALERT
    * SET\_ALERT\_BUTTON\_PROPERTY
    * SET\_ALERT\_PROPERTY
    * SHOW\_ALERT
- 块构建器：
    * FIND\_BLOCK
    * GET\_BLOCK\_PROPERTY
    * GO\_BLOCK
    * SET\_BLOCK\_PROPERTY
- 项目构建器：
    * CHECKBOX\_CHECKED
    * CONVERT\_OTHER\_VALUE
    * DISPLAY\_ITEM
    * FIND\_ITEM
    * GET\_ITEM\_INSTANCE\_PROPERTY
    * GET\_ITEM\_PROPERTY
    * GET\_RADIO\_BUTTON\_PROPERTY
    * GO\_ITEM
    * IMAGE\_SCROLL
    * IMAGE\_ZOOM
    * IMAGE\_ZOOM
    * PLAY\_SOUND
    * READ\_IMAGE\_FILE
    * READ\_SOUND\_FILE
    * RECALCULATE
    * SET\_ITEM\_INSTANCE\_PROPERTY
    * SET\_ITEM\_PROPERTY
    * SET\_ITEM\_PROPERTY
    * SET\_RADIO\_BUTTON\_PROPERTY
    * SET\_RADIO\_BUTTON\_PROPERTY
    * WRITE\_IMAGE\_FILE
    * WRITE\_SOUND\_FILE

- LOV构建器：
    * FIND\_LOV
    * GET\_LOV\_PROPERTY
    *