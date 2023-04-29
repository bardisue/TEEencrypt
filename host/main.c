
#include <err.h>
#include <stdio.h>
#include <string.h>

#include <tee_client_api.h>

#include <TEEencrypt_ta.h>

int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	char plaintext[64] = {0,};
	char ciphertext[64] = {0,};
	char encKey[3];
	int len=64;

	if(strcmp(argv[1], "-e")==0){
                	res = TEEC_InitializeContext(NULL, &ctx);
		        res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
		        memset(&op, 0, sizeof(op));

			op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_VALUE_INOUT, TEEC_NONE, TEEC_NONE);
             		op.params[0].tmpref.buffer = plaintext;
                	op.params[0].tmpref.size = len;

                	FILE* tmpR = fopen(argv[2], "r");
                	fread(plaintext, sizeof(plaintext), 1, tmpR);
                	fclose(tmpR);

	                printf("Plaintext: %s\n", plaintext);

	                memcpy(op.params[0].tmpref.buffer, plaintext, len);

	                res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_GET, &op, &err_origin);
	                res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op, &err_origin);

	                memcpy(ciphertext, op.params[0].tmpref.buffer, len);

			printf("Ciphertext: %s", ciphertext);

			encKey[0] = op.params[1].value.a;
	                encKey[1] = '\0';
	                //strcat(ciphertext, encKey);

	                FILE* tmpW = fopen("./encText.txt", "w");
	                fwrite(ciphertext, strlen(ciphertext), 1, tmpW);
	                fclose(tmpW);

			FILE* tmpW2 = fopen("./encKey.txt", "w");
	                fwrite(encKey, strlen(encKey), 1, tmpW2);
	                fclose(tmpW2);
	    	TEEC_CloseSession(&sess);

	    	TEEC_FinalizeContext(&ctx);
    	}

	else if(strcmp(argv[1], "-d")==0){
			res = TEEC_InitializeContext(NULL, &ctx);
		        res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
		        memset(&op, 0, sizeof(op));
			op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_VALUE_INOUT, TEEC_NONE, TEEC_NONE);
	                op.params[0].tmpref.buffer = ciphertext;
	                op.params[0].tmpref.size = len;

	                FILE* tmpR = fopen(argv[2], "r");
	                fread(ciphertext, sizeof(ciphertext), 1, tmpR);
	                fclose(tmpR);

	                FILE* tmpR2 = fopen(argv[3], "r");
	                fread(encKey, sizeof(encKey), 1, tmpR2);
	                fclose(tmpR2);

			memcpy(op.params[0].tmpref.buffer, ciphertext, len);
			op.params[1].value.a = encKey[0];
	
			printf("Ciphertext: %s\n", ciphertext);
			printf("encKey: %d\n", encKey[0]);

	                res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op, &err_origin);

	                memcpy(plaintext, op.params[0].tmpref.buffer, len);
	                printf("Plaintext: %s\n", plaintext);

	                FILE* tmpW = fopen("./decText.txt", "w");
	                fwrite(plaintext, strlen(plaintext), 1, tmpW);
	                fclose(tmpW);

			TEEC_CloseSession(&sess);
        		TEEC_FinalizeContext(&ctx);
	}

	return 0;
}
