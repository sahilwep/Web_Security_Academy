# CSRF : Cross Site Request Frogery 

* CSRF is a web sec vulnerability that allows an attacker to induce users to perform actions that they are not intend to perform. It allows an attacker to partly circumvent the same origin policy, which is designed to prevent different websites from interfering with each other.

![CSRF-](https://reflectoring.io/images/posts/csrf/csrf-intro_hua1478ce17fadc128f4bcdf5651ad3b7f_65290_731x0_resize_box_3.png)

## Impact : 

* A Successful SSRF attack cause the victim user to carry out an action unintentionally.
* For example, this might be the change the email address on their account, to change their password, or to make a funds transfer.Depending upon the nature of action the attacker might be able to gain full control over the user account.If the compromised user has privilege role within the application, then in this case the attacker able to take full control to all the application data and functionality.

## CSRF Working :

* For CSRF attack to be possible we need 3 condition that must be in place :
  *  `A relevant action` : There is a action within the application that the attacker has reason to induce.This might be a privilege action (such as modifying permission for other users ) or any action on user-specific data (such as changing the user own password).
  *  `Cookie-based session handling` : Mean when we do any action we need to make a HTTP request, & that application relies solely on session cookies to identify the user who has made request, there is no other mechanism in place for tracking the session or validating user request.
  * `No Unpredictable request parameter` : The request that perform the action do not contain any parameters whose values the attacker cannot determine or guess. For example, when causing a user to change their password, the function is not vulnerable if an attacker needs to know the values of the existing password.

> For example, suppose an application contains a function that lets the user change the email address on their account. when a user perform this action, they make an HTTP request like following:
```plain
POST /email/change HTTP/1.1
Host: vulnerable-website.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 30
Cookie: session=yvthwsztyeQkAPzeQ5gHgTvlyxHfsAfE

email=john@normal-user.com
```
> This meets the condition for CSRF:

- The action of changing the email address on a user's account is of intrest to an attacker. Following this action, the attacker will typically be able to trigger a password reset and take full control of the user account.

- The application uses a session cookie to identify which user issued the request. Their are no other tokens or mechanisms in place to track user sessions.

- The attacker can easily determine the values of the request parameters that are needed to perform the action.

> With these condition in place, the attacker can construct a web page containing the following HTML:

```html
<html>
    <body>
        <form action="https://vulnerable-website.com/email/change" method="POST">
            <input type="hidden" name="email" value="pwned@evil-user.net" />
        </form>
        <script>
            document.forms[0].submit();
        </script>
    </body>
</html>
```

> If a victum user visit the attacker web page, the following will happen:

- The attacker page will triger an HTTP request to the vulnerable web site.
- If the user is logged in to the vulnerable web site, thir browser will automatically include thir session cookie in the request (assuming SameSite Cookies are not being used).
- The vulnerable web site will process the request in the normal way, treat it as having been made by the victum user, and change their email address.


> NOTE : CSRF is normally describe in relation to cooke-based session handling, it also arises in other context where the application automatically add some user credintials to request, such as HTTP Basic Authentication and certificate-based Authentication.

> Summary : Suppose a Web-app is vulnerable to CSRF, it has function to change email, attacker will craft a HTTP Form for changing email and send it to the user by XSS or any method and leverage the user permission to takeover his/her account. 

## How to construct a CSRF Attack :

- Manually creating the HTML needed for a CSRF exploit can be cumbersome, particularly where the desired request contains a large number of parameters, or there are other quirks in the request. The easiest way to construct a CSRF exploit is using the `CSRF Poc Generator` that is built in to Burpsuit pro.

- Select a request anywhere in burpsuit that you want to test or exploit.
- Form the right click context menu, select Engament Tools/Generate CSRF PoC.
- Burp Suit generate some HTML that will trigger the selected request(minus cokkies, which will be added automatically by the victum browser.)
- You can tweak various option in CSRF PoC generator to fine-tune aspect of the attack. You might need to do this in some unusual situations to deal with quirky features of requests.
- Copy the generated HTML into a web page, view it in a browser that is logged in to the bulnerable web site, and test whether the intended request is issude sucussfully and the desired action occurs. 


### Manually 

> For construct the manually CSRF, we need to analyse the source page and know the `forms` that is submitted in the user account.

> example : The web-app has fucntion to change the email, we can construct CSRF like this : 

```html
<html>
    <body>
        <form action="https://vulnerable-website.com/email/change" method="POST">
            <input type="hidden" name="email" value="pwned@evil-user.net" />
        </form>
        <script>
            document.forms[0].submit();
        </script>
    </body>
</html>
```
- When user click this page, the form for change email is automatically submit, and his email is changed.  

## How to deliver a CSRF exploit :

- The delivery machenism for cross-site request forgery attacks are essintially the same as for reflected XXS. Typically, the attacker will place the malicious HTML onto a web site that they control, and then induce victims to visit that web site. this might by done by feeding the user a link to the web site, via an email or social media message. or if the attacker is placed into a popular web site(for example, in a user comment), they might just wait for user to visit the web site.

- Note that some simple CSRF exploit employ the GET method and can be fully self-contained with a single URL on a vulnerabel web site. in this situation, the attacker may not need to employ an external site, and can directly feed victims a malicious URL on the vulnerable domain. in the preceding example, if the request to change email address can be preformed with GET methods, then a self-contained attack would look like this:

```html
<img src="https://vulnerable-website.com/email/change?email=pwned@evil-user.net">
```



## Resource : 
* [CSRF](https://portswigger.net/web-security/csrf)
* [CSRF](https://learn.snyk.io/lessons/csrf-attack/javascript/)
* [CSRF](https://reflectoring.io/complete-guide-to-csrf/)
