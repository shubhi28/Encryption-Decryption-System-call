#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <openssl/md5.h>
#include "common.h"

#ifndef __NR_xcrypt
#error xcrypt system call not defined
#endif

/* Fxn converts the passphrase provided by user into MD5 Hash Key */
char * plaintextToMD5 (const char *password)
{
    	MD5_CTX context;
    	unsigned char *digest = (void*)malloc(16);

    	MD5_Init(&context);
	MD5_Update(&context, password, strlen(password));
    	MD5_Final(digest, &context);

    	return (void*)digest;	
}

int main(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind, optopt;
	struct inputs args;
	int rc;
	int flagp=0;
	int flage=0;
	int flagd=0;
	int error=0;
	char* keybuf;
	while(1){
		int c ;
		c= getopt(argc, argv, ":edp:h");
		if (c == -1)
			break;
		switch(c){
			case 'p':
				keybuf = optarg;
				flagp +=1;
				break;
			case 'e':
				if(flagd){
					printf("File can either be encrypted or decrypted !!!\n");
					error+=1;
				}
				else	{
					args.flag = 1;
					flage+=1;
				}	
				break;
			case 'd':
				if(flage){
                                        printf("File can either be Encrypted or Decrypted !!!\n");
                                        error+=1;
                                }
                                else    {
                                        args.flag = 0;
					flagd+=1;                                         
                                }
				break;
			case 'h':
				printf("Use -p option to provide password\n Use -d or -e to decrypt or encrypt file\n");
				break;
			case ':':
				printf("Option -%c requires argument\n",optopt);
				error+=1;
				break;
			case '?':
           			fprintf(stderr,"Unknown option character `\\x%x'.\n",optopt);
				return 1;
			default:
				break;
		}
	}

	if(flagp==0){
		printf("Please input your PASSWORD\n");
		exit(2);
	}

	if(flage==0){
		if(flagd==0){	
			printf("Provide flags to encrypt or decrypt\n");
			exit(2);
		}
	}

	if(error) {
		printf("Invalid arguments are provided\n");
		exit(2);
	}

	if(optind!= argc -2){
		printf("Missing arguments\n");
		exit(0);
	}

	args.keylen = 16;
	args.in=argv[optind++];
	args.out=argv[optind++];
	
	//printf("In Userspace\n");
	//printf("in=%s\n",args.in);
	//printf("out=%s\n",args.out);
	
	/* generate MD5 Hash key */
	unsigned char *key= NULL;
	key =(void*)plaintextToMD5((const char *)keybuf);

	/* passing generated key in keybuf */
	args.keybuf = (void*)malloc(16);
	memcpy(args.keybuf,key,16);
	
	/* passing structure to arguments */
	void *dummy = (void *) &args;	
  	rc = syscall(__NR_xcrypt, dummy);
	if (rc == 0)
		printf("syscall returned %d\n", rc);
	else
		printf("syscall returned %d (errno=%d)\n", rc, errno);

	exit(rc);
}
