/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
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
	char key[2] = {0, };
	int len=64;
	FILE* pt;		// plain text
	FILE* ek;		// encrypt key
	FILE* et;		// encrypt text
	FILE* dt;		// decrypt text
//	int key[1] = {0};


	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = 0;
	
	if(strcmp(argv[1], "-e") == 0) {
		printf("key encrypt start\n");
		// key encrypt
		/*
		op.params[0].tmpref.buffer = key;
		op.params[0].tmpref.size = sizeof(key);
		memcpy(op.params[0].tmpref.buffer, key, sizeof(key));
		*/ 
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_GET_KEY, &op,
					 &err_origin);
		
		// memcpy(key, op.params[0].tmpref.buffer, sizeof(key));

		printf("encrypt key : %ld\n", op.params[0].value.a);
		

		ek = fopen("encrypt_key.txt", "w");
		fprintf(ek, "%d", op.params[0].value.a);
		fclose(ek);
		
		printf("file read start");
		//file read && encrypt
		pt = fopen("plaintext.txt","r");
		fseek(pt, 0, SEEK_END);
		int size = ftell(pt);
		fseek(pt, 0, SEEK_SET);
		fread(plaintext, size, 1, pt);
		fclose(pt);
		op.params[1].tmpref.buffer = plaintext;
		op.params[1].tmpref.size = len;
		
		printf("========================Encryption========================\n");
		memcpy(op.params[1].tmpref.buffer, plaintext, len);

		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,
					 &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);

		memcpy(ciphertext, op.params[1].tmpref.buffer, len);
		et = fopen("Ciphertext.txt", "w");
		printf("Ciphertext : %s\n", ciphertext);
		fwrite(ciphertext, strlen(ciphertext), 1, et);
		fclose(et);
	
	}
	if(strcmp(argv[1], "-d") == 0){

		printf("========================Decryption========================\n");
		
		et = fopen("Ciphertext.txt","r");
		fscanf(et, "%s", ciphertext);
		fclose(et);
		printf("ciphertext : %s\n", ciphertext);
		
		printf("enc key read start\n");
		ek = fopen("encrypt_key.txt", "r");
		fscanf(ek, "%s", key);
		fclose(ek);

		printf("enc key read end\n");
		op.params[0].value.a = atoi(key);
		printf("enc key val? : %d\n", op.params[0].value.a);

		op.params[1].tmpref.buffer = ciphertext;
		op.params[1].tmpref.size = len;
		memcpy(op.params[1].tmpref.buffer, ciphertext, len);

		printf("before func\n");
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
				 &err_origin);
		printf("dec end\n");
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
				res, err_origin);
		memcpy(plaintext, op.params[1].tmpref.buffer, len);
		printf("Plaintext : %s\n", plaintext);
		dt = fopen("Decrypt_text.txt", "w");
		fwrite(plaintext, strlen(plaintext), 1, dt);
		TEEC_CloseSession(&sess);
		TEEC_FinalizeContext(&ctx);
		fclose(dt);
	
	}

	return 0;
}
