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
