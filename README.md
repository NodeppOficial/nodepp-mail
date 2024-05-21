# NODEPP-MAIL
Run a simple **SMTP Client** in Nodepp

## Example
```cpp
#include <nodepp/nodepp.h>
#include <nodepp/ssl.h>
#include "mail.h"

using namespace nodepp;

void onMain() {

    ssl_t ssl ( "./ssl/cert.key", "./ssl/cert.crt" );
    mail_t mail ( "smtp://smtp.gmail.com:587", &ssl );

    mail_auth_t auth = {
        .user = "bececrazy2@gmail.com",
        .pass = "MyGmailPassword",
        .type = MAIL_AUTH_OAUTH
    };

    mail.send( auth, "becerracenmanueld@gmail.com", "subject", "Hello World!" );

}
```

## Compilation
`g++ -o main main.cpp -I ./include -lssl -lcrypto ; ./main`