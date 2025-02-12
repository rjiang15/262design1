# Design Exercise 1: Wire Protocols

For this design exercise, we built a simple, client-server chat application. The application allows users to send and receive text messages. There's a centralized server that will mediate the passing of messages. The application allows:

- Creating an account. The user supplies a unique (login) name. If there is already an account with that name, the user is prompted for the password. If the name is not being used, the user is prompted to supply a password. The password is not be passed as plaintext.
- Log in to an account. Using a login name and password, log into an account. An incorrect login or bad user name displays an error. A successful login displays the number of unread messages.
- List accounts, or a subset of accounts that fit a text wildcard pattern. If there are more accounts than can comfortably be displayed, we allow iterating through the accounts.
- Send a message to a recipient. If the recipient is logged in, deliver immediately; if not the message is stored until the recipient logs in and requests to see the message. 
- Read messages. If there are undelivered messages, display those messages. The user can specify the number of messages they want delivered at any single time.
- Delete a message or set of messages. Once deleted messages are gone.
- Delete an account. We specify the semantics of deleting an account that contains unread messages.

The client offers a reasonable graphical interface. We also designed the wire protocol—what information is sent over the wire. Communication is done using sockets constructed between the client and server. It's possible to have multiple clients connected at any time. We built two implementations:

1. A custom wire protocol engineered based on class
2. One using JSON.

We measure the size of the information passed between the client and the server and wrote up a comparison in this engineering notebook, along with some remarks on what the difference makes to the efficiency and scalability of the service.
