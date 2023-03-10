# CSRF : Cross Site Request Frogery 

* CSRF is a web sec vulnerability that allows an attacker to induce users to perform actions that they are not intend to perform. It allows an attacker to partly circumvent the same origin policy, which is designed to prevent different websites from interfering with each other.

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








