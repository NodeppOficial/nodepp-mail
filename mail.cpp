#include <nodepp/nodepp.h>
#include <nodepp/ssl.h>
#include "mail.h"

using namespace nodepp;

void onMain() {

    ssl_t ssl ( "./ssl/cert.key", "./ssl/cert.crt" );
    mail_t mail ( "smtp://smtp.gmail.com:587", &ssl );

    mail_auth_t auth = {
        .user = "bececrazy2",
        .pass = "0123456789",
        .serv = "google.com",
        .type = MAIL_AUTH_OAUTH
    };

    mail.send( auth, "becerracenmanueld@gmail.com", "tarea", "hola mundo!" );

}