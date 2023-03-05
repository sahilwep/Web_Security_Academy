# CSRF : Cross Site Request Frogery 

* CSRF is a web sec vulnerability that allows an attacker to induce users to perform actions that they are not intend to perform. It allows an attacker to partly circumvent the same origin policy, which is designed to prevent different websites from interfering with each other.

## Impact : 

* A Successful SSRF attack cause the victim user to carry out an action unintentionally.
* For example, this might be the change the email address on their account, to change their password, or to make a funds transfer.Depending upon the nature of action the attacker might be able to gain full control over the user account.If the compromised user has privilege role within the application, then in this case the attacker able to take full control to all the application data and functionality.

## CSRF Working :

* For CSRF attack to be possible we need 3 condition that must be in place :
  *  `A relevant action` : There is a action within the application that the attacker has reason to induce.This might be a privilege action (such as modifying permission for other users ) or any action on user-specific data (such as changing the user own password).
  *  `Cookie-based session handling` : Mean when we do any action we need to make a HTTP request, & that application relies solely on session cookies to identify the user who has made request, there is no other mechanism in place for tracking the session or validating user request.
  * `No Unpredictable request parameter` : The 










