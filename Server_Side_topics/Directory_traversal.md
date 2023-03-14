# Directory Traversal

* Directory traversal is also known as path traversal is a web security vulnerability that allows an attacker to read arbitrary files on the server that is running an application.
* This might include application code and data, credentials for back-end system, and sensitive files.
* In some cases, an attacker might be able to write to arbitrary files on the server, allowing them to modify application data or behavior, and ultimately take full control of the server.

## Reading arbitrary files via directory traversal
* Consider a shopping application that displays images of items for sale. Images are loaded via some HTML like following: 

```html
<img src="/loadImage?filename=218.png">
```

* The `loadImage` Url takes `filename` parameter and return the contents of the special file. The image files themselves are stored on disk in the location `/var/www/images/`. To return an image, the application appends the requested filename to his base directory and uses a filesystem API to read the contents of the file. In the above case, the application reads from the following file path:

```plain
/var/www/images/281.png
```

* The application implements no defense against directory traversal attack, so an attacker can request the following URL to retrieve an arbitrary file from the server's filesystem.

```plain
https://insecure-website.com/loadImage?filename=../../../etc/passwd
```
This cause an application to read from the file path:

```plain
/var/www/images/../../../etc/passwd
```
The sequence `../` is valid within a file path, and means to setup up one level in the directory structure. The three consecutive `../` sequences setup up from `/var/www/images/` to the filesystem root, and so the file is actually read is:

```plain
/etc/passwd
```

* On Unix-based operating system, this is a standard file containing details of the user that are registered on the server.
* On Windows, both `../` and `..\` are valid directory traversal sequences, and an equivalent attack to retrieve a standard operating system file would be:

```plain
https://insecure-website.com/loadImage?filename=..\..\..\windows\win.ini
```

## Common Obstacles to exploiting file path traversal vulnerabilities


