#ifndef NODEPP_MAIL
#define NODEPP_MAIL

#include <nodepp/encoder.h>
#include <nodepp/socket.h>
#include <nodepp/ssl.h>
#include <nodepp/dns.h>
#include <nodepp/url.h>

namespace nodepp {

    enum AUTH_TYPE {
         MAIL_AUTH_PLAIN,
         MAIL_AUTH_OAUTH
    };

    struct mail_header_t {
        string_t message;
        int      status;
    };

    struct mail_auth_t {
        string_t user; string_t pass;
        AUTH_TYPE type=MAIL_AUTH_PLAIN;
    }; 

}

namespace nodepp { class mail_t {
protected:

    struct NODE {
        socket_t fd ;
        int state =1;
        bool extd =0;
        bool tlsl =0;
        ssl_t ssl, ctx;
        string_t hostname;
    };  ptr_t<NODE> obj;

    mail_header_t read_header() const noexcept {
        mail_header_t result; auto data = read();
        result.status = string::to_int( data.slice(0,3) );
        result.message= data.slice(4).get(); return result;
    }

    void handshake() const {

        auto header = read_header(); if( header.status >= 400 ){ 
            process::error("Can't connect to the server");
        }

        push("EHLO nodepp-mail");

        header = read_header();  if ( header.status <  400 )
        { obj->extd=1; return; } if ( header.status >= 500 ){ 
            process::error("Can't connect to the server");
        }

        push("HELO nodepp-mail");

        header = read_header(); if( header.status < 400 )
        { return; } if ( header.status >= 500 ){ 
            process::error("Can't connect to the server");
        }

    }

    void tls() const {
        if( obj->ctx.get_ctx() == nullptr ){ return; }
        push("STARTTLS"); auto header = read_header();
        
        if( header.status >= 500 ){
            process::error("auth pass not accepted");
        } elif( header.status >= 400 ) { return; }

        obj->ssl = ssl_t( obj->ctx, obj->fd.get_fd() ); 
        obj->ssl.set_hostname( obj->hostname );

        if( obj->ssl.connect() <= 0 )
          { process::error("Error while handshaking TLS"); }

        obj->tlsl = 1;
    }

    void auth_plain( mail_auth_t& auth ) const {
        auto pass = encoder::base64::get(
            string::format("\0%s\0%s",auth.user.get(),auth.pass.get())
        );  push( string::format("AUTH PLAIN %s", pass.get() ) );
        auto header = read_header(); if( header.status >= 400 ){
             process::error("auth pass not accepted");
        }
    }

    void auth_oauth( mail_auth_t& auth ) const {
        push( string::format("AUTH XOAUTH2 %s", auth.pass.get() ) );
        auto header = read_header(); if( header.status >= 400 ){
             process::error("auth pass not accepted");
        }
    }

    void mail_from( string_t email ) const {
        push( string::format("MAIL FROM: <%s>", email.get() ) );
        auto header = read_header(); if( header.status >= 400 ){
             process::error("auth pass not accepted");
        }
    }

    void mail_to( string_t email ) const {
        push( string::format("RCPT TO: <%s>", email.get() ) );
        auto header = read_header(); if( header.status >= 400 ){
             process::error("auth pass not accepted");
        }
    }

    void send_msg( string_t message ) const { push( "DATA" );
        auto header = read_header(); if( header.status >= 400 ){
             process::error("auth pass not accepted");
        }    write( message ); push("<CR><LF>.<CR><LF>");
    }

public:

   ~mail_t () {
        if( obj.count() > 1 ){ return; }
        if( obj->state == 0 ){ return; }
        free();
    }

    mail_t ( string_t uri ) : obj( new NODE ){

        if( !url::is_valid( uri ) )
          { process::error( "Invalid URL" ); }  

        auto prs = url::parse( uri );

        obj->fd = socket_t();
        obj->fd.IPPTOTO= IPPROTO_TCP;
        obj->hostname = prs.hostname;
        obj->fd.socket( dns::lookup(prs.hostname), prs.port );

        if( obj->fd.connect() < 0 ) { obj->fd.close(); 
            process::error("Can't Connect to Server"); 
        }

    }

    mail_t ( string_t uri, ssl_t* ssl ) : obj( new NODE ){

        if( !url::is_valid( uri ) )
          { process::error( "Invalid URL" ); }  

        auto prs = url::parse( uri );

        obj->ctx = *ssl;
        obj->fd  = socket_t();
        obj->fd.IPPTOTO= IPPROTO_TCP;
        obj->hostname = prs.hostname;
        obj->fd.socket( dns::lookup(prs.hostname), prs.port );

        if( obj->ctx.create_client() == -1 )
          { process::error("Error Initializing SSL context"); }

        if( obj->fd.connect() < 0 ) { obj->fd.close(); 
            process::error("Can't Connect to Server"); 
        }

    }

    int send ( mail_auth_t auth, string_t email, string_t subject, string_t msg ) const {
    coStart
        handshake(); if ( obj->extd ){ tls(); } switch ( auth.type ) {
            case MAIL_AUTH_PLAIN: auth_plain( auth ); break;
            case MAIL_AUTH_OAUTH: auth_oauth( auth ); break;
            default: process::error("AUTH NOT SUPPORTED"); break; 
        }   coSet(1); goto NEXT; coYield(1); NEXT:;
        mail_from( auth.user ); mail_to( email ); send_msg( msg );
    coGoto(1);
    coStop
    }

    int write( string_t message ) const noexcept {
        if( obj->state != 1 || message.empty() ){ return 0; } ulong data = 0; int state = 0; do { do { 
             if ( obj->tlsl ){ state = obj->ssl._write( message.data()+data, message.size()-data ); }
             else            { state = obj->fd ._write( message.data()+data, message.size()-data ); }
             if ( true /* state==-2 */ )    { process::next(); }
        } while ( state==-2 ); if( state>0 ){ data += state;   }
        } while ( state>=0 && data<message.size() ); return state;
    }

    int push( string_t message ) const noexcept { return write( message + "\n" ); }

    string_t read() const noexcept {
        if( obj->state != 1 ){ return nullptr; } 
        string_t buffer ( UNBFF_SIZE, '\0' ); int state = 0; do {
            if ( obj->tlsl ){ state = obj->ssl._read( buffer.data(), buffer.size() ); }
            else            { state = obj->fd ._read( buffer.data(), buffer.size() ); }
            if ( state < 0 && state != -2 ){ return nullptr; }
        } while( state == -2 ); return string_t ( buffer.get(), state );
    }

    void close() const noexcept {
        if( !obj->fd.is_available() ){ return; }
             push( "QUIT" ); free();
    }

    void free() const noexcept {
        if( obj->state == 0 ){ return; }
            obj->state =  0; obj->fd.close();
    }

};}

#endif
