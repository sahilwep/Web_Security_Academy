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

* Before we look at how to exploit the uplaod vulnerability, it's important that you have a basic understanding of how servers handel request for static files.

* 