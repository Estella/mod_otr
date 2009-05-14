/* driver for the mod_otr for ejabberd
 * Copyright 2007 Olivier Goffart <ogoffart@kde.org>
 * Under GNU GPLv2.  http://www.gnu.org/licenses/gpl.html */
 
/*  This driver is used to do a man in the middle of the OTR protocol
    See the mod_otr.erl for more information */
    
/* Version 0.1  2007-03-29 */


#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include <erl_driver.h>
#include <ei.h>

#include <libotr/privkey.h>
#include <libotr/proto.h>
#include <libotr/message.h>
#include <libotr/userstate.h>

//#define DEBUG(...)	fprintf(stderr, __VA_ARGS__ )
#define DEBUG(...)
#define ERROR(...)	fprintf(stderr, __VA_ARGS__ )



//BEGIN  code from expat_erl.c

#define EI_ENCODE_STRING_BUG

#ifdef EI_ENCODE_STRING_BUG

/*
 * Workaround for EI encode_string bug
 */

#define put8(s,n) do { \
  (s)[0] = (char)((n) & 0xff); \
  (s) += 1; \
} while (0) 

#define put16be(s,n) do { \
  (s)[0] = ((n) >>  8) & 0xff; \
  (s)[1] = (n) & 0xff; \
  (s) += 2; \
} while (0)

#define put32be(s,n) do {  \
  (s)[0] = ((n) >>  24) & 0xff; \
  (s)[1] = ((n) >>  16) & 0xff; \
  (s)[2] = ((n) >>  8) & 0xff;  \
  (s)[3] = (n) & 0xff; \
  (s) += 4; \
} while (0)

int ei_encode_string_len_fixed(char *buf, int *index, const char *p, int len)
{
    char *s = buf + *index;
    char *s0 = s;
    int i;

    if (len <= 0xffff) {
	if (!buf) s += 3;
	else {
	    put8(s,ERL_STRING_EXT);
	    put16be(s,len);
	    memmove(s,p,len);	/* unterminated string */
	}
	s += len;
    }
    else {
	if (!buf) s += 6 + (2*len);
	else {
	    /* strings longer than 65535 are encoded as lists */
	    put8(s,ERL_LIST_EXT);
	    put32be(s,len);

	    for (i=0; i<len; i++) {
		put8(s,ERL_SMALL_INTEGER_EXT);
		put8(s,p[i]);
	    }

	    put8(s,ERL_NIL_EXT);
	}
    }

    *index += s-s0; 

    return 0; 
}

int ei_encode_string_fixed(char *buf, int *index, const char *p)
{
    return ei_encode_string_len_fixed(buf, index, p, strlen(p));
}

int ei_x_encode_string_len_fixed(ei_x_buff* x, const char* s, int len)
{
    int i = x->index;
    ei_encode_string_len_fixed(NULL, &i, s, len);
    if (!x_fix_buff(x, i))
	return -1;
    return ei_encode_string_len_fixed(x->buff, &x->index, s, len);
}

int ei_x_encode_string_fixed(ei_x_buff* x, const char* s)
{
    return ei_x_encode_string_len_fixed(x, s, strlen(s));
}

#else

#define ei_encode_string_len_fixed(buf, index, p, len) \
        ei_encode_string_len(buf, index, p, len)
#define ei_encode_string_fixed(buf, index, p) \
        ei_encode_string(buf, index, p)
#define ei_x_encode_string_len_fixed(x, s, len) \
        ei_x_encode_string_len(x, s, len)
#define ei_x_encode_string_fixed(x, s) \
        ei_x_encode_string(x, s)

#endif

//END code from expat_erl.c






static OtrlPrivKey *get_privkey(OtrlUserState us, const char *accountname, const char *protocol)
{
    OtrlPrivKey *privkey = otrl_privkey_find( us, accountname,	protocol);
    if(!privkey)
    {
        DEBUG("OTR_DRV: get_privkey:  generate privatekey for %s \r\n" , accountname);
        int err = otrl_privkey_generate( us, "wallet", accountname, protocol);
        if( err )
            ERROR("OTR_DRV: error when creating private key for account %s : %s \r\n", accountname , gcry_strerror(err));
        privkey = otrl_privkey_find( us, accountname, protocol);
    }
    return privkey;
}


static gcry_error_t go_encrypted(const OtrlAuthInfo *auth, void * data )
{
    struct context *context = (struct context*) data;
    gcry_error_t err;
    

    /* See if we're talking to ourselves */
    if (!gcry_mpi_cmp(context->auth.their_pub, context->auth.our_dh.pub)) {
	/* Yes, we are. */
        DEBUG("OTR_DRV: go_encrypted: we are talking to ourself \r\n" );
    }

    /* Copy the information from the auth into the context */
    memmove(context->sessionid, context->auth.secure_session_id, 20);
    context->sessionid_len = context->auth.secure_session_id_len;
    context->sessionid_half = context->auth.session_id_half;
    context->protocol_version = context->auth.protocol_version;

    context->their_keyid = context->auth.their_keyid;
    gcry_mpi_release(context->their_y);
    gcry_mpi_release(context->their_old_y);
    context->their_y = gcry_mpi_copy(context->auth.their_pub);
    context->their_old_y = NULL;

    if (context->our_keyid - 1 != context->auth.our_keyid ||
	gcry_mpi_cmp(context->our_old_dh_key.pub,
	    context->auth.our_dh.pub)) {
	otrl_dh_keypair_free(&(context->our_dh_key));
	otrl_dh_keypair_free(&(context->our_old_dh_key));
	otrl_dh_keypair_copy(&(context->our_old_dh_key),
		&(context->auth.our_dh));
	otrl_dh_gen_keypair(context->our_old_dh_key.groupid,
		&(context->our_dh_key));
	context->our_keyid = context->auth.our_keyid + 1;
    }

    /* Create the session keys from the DH keys */
    otrl_dh_session_free(&(context->sesskeys[0][0]));
    err = otrl_dh_session(&(context->sesskeys[0][0]),
	&(context->our_dh_key), context->their_y);
    if (err) return err;
    otrl_dh_session_free(&(context->sesskeys[1][0]));
    err = otrl_dh_session(&(context->sesskeys[1][0]),
	&(context->our_old_dh_key), context->their_y);
    if (err) return err ;

    context->generation++;

    context->msgstate = OTRL_MSGSTATE_ENCRYPTED;

    return err;
}



/**
 * if plaintext is not null,  both message_out and plaintext must be free'ed,   
 * else, nothing may be free'ed, message_out will be automatically free'ed next time this function enter
 */
static int message_receiving(const char *message, char **message_out, char **plaintext, OtrlUserState us, const char *sender_jid, const char *receiver_jid, const char* protocol)
{
    //TODO: fragement

    struct context * context_sender;
    struct context * context_receiver;

    context_sender = otrl_context_find(us, sender_jid, receiver_jid, protocol,
	    1, NULL, NULL, NULL);
    context_receiver = otrl_context_find(us, receiver_jid, sender_jid, protocol,
	    1, NULL, NULL, NULL);

    OtrlMessageType msgtype;
    msgtype = otrl_proto_message_type( message );

    OtrlPrivKey *privkey;
    int haveauthmsg;
    gcry_error_t err;
     
    OtrlTLV *tlvs;
    unsigned char flags;
    
    *plaintext = NULL;
    *message_out = NULL;
    
    
    
    switch(msgtype) {
        case OTRL_MSGTYPE_QUERY:  //nothing to do
            return 0; 
        case OTRL_MSGTYPE_DH_COMMIT:  //bob -> alice
            DEBUG("OTR_DRV: message_receiving:  DH_COMMIT \r\n");
            err = otrl_auth_handle_commit(&(context_sender->auth), message);
            if(err)
            {
                ERROR("OTR_DRV: error when reading DH_COMMIT message : %s \r\n", gcry_strerror(err));
                return err;
            }
            
            err=otrl_auth_start_v2( &(context_receiver->auth) );
            if(err)
            {
                ERROR("OTR_DRV: error when creating fake DH_COMMIT message : %s \r\n", gcry_strerror(err));
                return err;
            }
            *message_out=context_receiver->auth.lastauthmsg;
            break;
        case OTRL_MSGTYPE_DH_KEY: //alice -> bob
            DEBUG("OTR_DRV: message_receiving:  DH_KEY \r\n");
            privkey = get_privkey( us , sender_jid , protocol  );
            if (privkey) {
                err = otrl_auth_handle_key(&(context_sender->auth), message, &haveauthmsg, privkey);
                if(err)
                {
                    ERROR("OTR_DRV: error when reading DH_KEY  message : %s \r\n", gcry_strerror(err));
                    return err;
                }
            }
            *message_out=context_receiver->auth.lastauthmsg;
            break;
        case OTRL_MSGTYPE_REVEALSIG: //bob -> alice
            DEBUG("OTR_DRV: message_receiving:  REVEALSIG \r\n");
            privkey = get_privkey( us , sender_jid , protocol  );
            if (privkey) {
                err = otrl_auth_handle_revealsig(&(context_sender->auth), message, &haveauthmsg, privkey, go_encrypted,context_sender);
                if(err)
                {
                    ERROR("OTR_DRV: error when reading REVEALSIG message : %s \r\n", gcry_strerror(err));
                    return err;
                }
            }
            *message_out=context_receiver->auth.lastauthmsg;
            break;
        case OTRL_MSGTYPE_SIGNATURE: //alice -> bob
            DEBUG("OTR_DRV: message_receiving:  SIGNATURE \r\n");
            err = otrl_auth_handle_signature(&(context_sender->auth), message, &haveauthmsg, go_encrypted,context_sender);
            if (err )
            {
                    ERROR("OTR_DRV: error when reading SIGNATURE message: %s \r\n", gcry_strerror(err) );
                    return err;
            }
            *message_out=context_receiver->auth.lastauthmsg;
            break;
        
        case OTRL_MSGTYPE_DATA:
            DEBUG("OTR_DRV: message_receiving:  DATA \r\n");
            err = otrl_proto_accept_data(plaintext, &tlvs, context_sender, message, &flags);
            //ignore error
            if (!(*plaintext))
            {
                ERROR("OTR_DRV:  error when decrypting DATA message : %s \r\n", gcry_strerror(err));
                otrl_tlv_free(tlvs);
                return err; //NOTE: what if err is == 0 ?  
            }
                
            err = otrl_proto_create_data(message_out, context_receiver, *plaintext, tlvs, flags);
            otrl_tlv_free(tlvs);
            if(err)
            {
                ERROR("OTR_DRV: error when encrypting DATA message: %s \r\n", gcry_strerror(err));
                return err;
            }
	    break;
        default:
            break;
    }
    return 0;
    
}

typedef struct {
    ErlDrvPort port;
    OtrlUserState userstate;
} otr_data;


static ErlDrvData otr_drv_start(ErlDrvPort port, char *buff)
{
   OTRL_INIT;
   otr_data* d = (otr_data*)driver_alloc(sizeof(otr_data));
   d->port = port;
   d->userstate =  otrl_userstate_create();
   otrl_privkey_read( d->userstate, "wallet" );
#ifndef TEST
   set_port_control_flags(port, PORT_CONTROL_FLAG_BINARY);
#endif
   
   return (ErlDrvData)d;
}

static void otr_drv_stop(ErlDrvData handle)
{
    otrl_userstate_free(((otr_data*)handle)->userstate);
    driver_free((char*)handle);
}



static int otr_drv_control(ErlDrvData drv_data,
                           unsigned int command,
                           char *buf, int len,
                           char **rbuf, int rlen)
{
    int i;
    int size;
    int index = 0;

    char *jid_sender, *jid_receiver, *body;
    otr_data* d = (otr_data*)drv_data;

    ei_decode_version(buf, &index, &i);
    ei_decode_tuple_header(buf, &index, &i);
    ei_get_type(buf, &index, &i, &size);
    jid_sender = malloc(size + 1); 
    ei_decode_string(buf, &index, jid_sender);

    ei_get_type(buf, &index, &i, &size);
    jid_receiver = malloc(size + 1); 
    ei_decode_string(buf, &index, jid_receiver);

    ei_get_type(buf, &index, &i, &size);
    body = malloc(size + 1); 
    ei_decode_string(buf, &index, body);
    
    DEBUG("OTR_DRV: ACTION  from='%s'  to='%s'  message='%s' \r\n" , jid_sender, jid_receiver, body);

    char *message_out;
    char *plaintext;
    ErlDrvBinary *b;
    ei_x_buff ei_buf;

    /*switch (command)
    {
    case MSGRECEIVING_COMMAND:
    default:*/
    message_receiving(body, &message_out, &plaintext, d->userstate, jid_sender, jid_receiver, "jabber");
    DEBUG("OTR_DRV: RESULT  message_out='%s'  plaintext='%s' \r\n" , message_out, plaintext);
    ei_x_new_with_version( &ei_buf );
    if( !message_out )
    {
        ei_x_encode_tuple_header( &ei_buf, 1 );
        ei_x_encode_atom( &ei_buf , "ignore");
    }
    else
    {
        ei_x_encode_tuple_header( &ei_buf, plaintext ? 3: 2);
        ei_x_encode_atom( &ei_buf , "ok");
        ei_x_encode_string_fixed( &ei_buf , message_out);
        if(plaintext)
            ei_x_encode_string_fixed( &ei_buf , plaintext);
    }
    size = ei_buf.index;
    b = driver_alloc_binary(size);
    memcpy(b->orig_bytes, ei_buf.buff, size);
    
    *rbuf = (char *)b;
   
    if(plaintext)
    {
        free(plaintext);
        free(message_out);
    }
    free(body);
    free(jid_sender);
    free(jid_receiver);
    ei_x_free(&ei_buf);
    return size;
}


#ifndef TEST

ErlDrvEntry otr_driver_entry = {
   NULL,			/* F_PTR init, N/A */
   otr_drv_start,	/* L_PTR start, called when port is opened */
   otr_drv_stop,		/* F_PTR stop, called when port is closed */
   NULL,			/* F_PTR output, called when erlang has sent */
   NULL,			/* F_PTR ready_input, called when input descriptor ready */
   NULL,			/* F_PTR ready_output, called when output descriptor ready */
   "otr_drv",		/* char *driver_name, the argument to open_port */
   NULL,			/* F_PTR finish, called when unloaded */
   NULL,			/* handle */
   otr_drv_control,	/* F_PTR control, port_command callback */
   NULL,			/* F_PTR timeout, reserved */
   NULL				/* F_PTR outputv, reserved */
};


DRIVER_INIT(otr_drv) /* must match name in driver_entry */
{
    return &otr_driver_entry;
}

#else
/*
int main()
{
    static const char *jid1 = "romeo@server1.com";
    static const char *jid2 = "julliet@server2.com";
    static const char *message = 
           "?OTR:AAICAAAAxGG5dLk7iDqmXhXaVu+m/sw4eoz9OQfkqhd3ubF3VHZxXV/W6cW+osALgP+7BW2"
           "m8kUxkIAgRErEdm2UntG2yUOceSayg8BxR37BzKmKMj6wcIVXrhrBeUcURFFq9eDf3+BexdPEQgj"
           "XRNoybiGEUwglMk3YGx66GRxKV774rft3KZzUYt8ooEfr69JwF4vKA8Qn48QbOuqLldo+POjzQVO"
           "dGOytVC2a8upwCPHKItkwVZIMYrBfUI6t1Ks2IUIky+MUEWcAAAAgq8HnNU780srfQSlxGTOJKefHZqc/WLZhX0OUkC5E11Q=.";
    
    ErlDrvPort port=0; data;
    ErlDrvData data = otr_drv_start(port, NULL);
    
    ei_x_buff ei_buf; ei_x_new_with_version( &ei_buf );  ei_x_encode_tuple_header( &ei_buf, 3 );
    ei_x_encode_string_fixed( &ei_buf , jid1);  ei_x_encode_string_fixed( &ei_buf , jid2);
    ei_x_encode_string_fixed( &ei_buf , message);
    
    char *buf;
    int size = otr_drv_control(data, 0, ei_buf.buff, ei_buf.index, &buf, 0);
    ei_x_free(&ei_buf);
    printf("Got the result size = %d  \n", size );
    free(buf);
    otr_drv_stop(data);
    return 0;
}

void *driver_alloc(size_t size)
{
    return  malloc(size);
}
ErlDrvBinary *driver_alloc_binary(int size)
{
    return  malloc(size + sizeof(long));
}
void driver_free(void *o)
{
    return free(o);
}
*/

#endif
