
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fstream>
#include "sodium.h"

#define CHUNK_SIZE 4096
#define SALTO printf("\n");

static int
encrypt(const char* target_file, const char* source_file,
    const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
    unsigned char  buf_in[CHUNK_SIZE];
    unsigned char  buf_out[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    FILE* fp_t, * fp_s;
    unsigned long long out_len;
    size_t         rlen;
    int            eof;
    unsigned char  tag;

    fp_s = fopen(source_file, "rb");
    fp_t = fopen(target_file, "wb");
    crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);
    fwrite(header, 1, sizeof(header), fp_t);
    do {
        rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
        eof = feof(fp_s);
        tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
        crypto_secretstream_xchacha20poly1305_push(&st, buf_out, &out_len, buf_in, rlen,
            NULL, 0, tag);
        fwrite(buf_out, 1, (size_t)out_len, fp_t);
    } while (!eof);
    fclose(fp_t);
    fclose(fp_s);
    return 0;
}

static int
decrypt(const char* target_file, const char* source_file,
    const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
    unsigned char  buf_in[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char  buf_out[CHUNK_SIZE];
    unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    FILE* fp_t, * fp_s;
    unsigned long long out_len;
    size_t         rlen;
    int            eof;
    int            ret = -1;
    unsigned char  tag;

    fp_s = fopen(source_file, "rb");
    fp_t = fopen(target_file, "wb");
    fread(header, 1, sizeof header, fp_s);
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {
        goto ret; /* incomplete header */
    }
    do {
        rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
        eof = feof(fp_s);
        if (crypto_secretstream_xchacha20poly1305_pull(&st, buf_out, &out_len, &tag,
            buf_in, rlen, NULL, 0) != 0) {
            goto ret; /* corrupted chunk */
        }
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL && !eof) {
            goto ret; /* premature end (end of file reached before the end of the stream) */
        }
        fwrite(buf_out, 1, (size_t)out_len, fp_t);
    } while (!eof);

    ret = 0;
ret:
    fclose(fp_t);
    fclose(fp_s);
    return ret;
}

int
main(void)
{
        unsigned char key1[crypto_secretstream_xchacha20poly1305_KEYBYTES];
        unsigned char key2[crypto_secretstream_xchacha20poly1305_KEYBYTES];
        unsigned char key3[crypto_secretstream_xchacha20poly1305_KEYBYTES];
        unsigned char temp1[crypto_secretstream_xchacha20poly1305_KEYBYTES];
        unsigned char temp2[crypto_secretstream_xchacha20poly1305_KEYBYTES];
        unsigned char temp3[crypto_secretstream_xchacha20poly1305_KEYBYTES];
        unsigned char pk[crypto_sign_PUBLICKEYBYTES];
        unsigned char sk[crypto_sign_SECRETKEYBYTES];
        unsigned char  buf_in[CHUNK_SIZE];
        
        unsigned long long out_len;
        size_t         rlen;
        int            eof;
        unsigned char  tag;
        if (sodium_init() != 0) {
            return 1;
        }
        crypto_sign_keypair(pk, sk);

        printf("--------------MENU-------------");
        SALTO
        printf("1.Generacion de claves.");
        SALTO
        printf("2.Cifrado de archivos.");
        SALTO
        printf("3.Descifrado de archivos.");
        SALTO
        printf("4.Firma de Archivos.");
        SALTO
        printf("5.Verificacion de firma.");
        SALTO

        printf("Generando claves... ");
        SALTO
    
        crypto_secretstream_xchacha20poly1305_keygen(temp1);
        crypto_secretstream_xchacha20poly1305_keygen(temp2);
        crypto_secretstream_xchacha20poly1305_keygen(temp3);

        FILE* fp1;
        FILE* fp2;
        FILE* fp3;
        fp1 = fopen("C:/Users/jplop/Documents/Tercer semestre/SEGURIDAD EN REDES/proyecto/clave1.txt", "w+");
        fp2 = fopen("C:/Users/jplop/Documents/Tercer semestre/SEGURIDAD EN REDES/proyecto/clave2.txt", "w+");
        fp3 = fopen("C:/Users/jplop/Documents/Tercer semestre/SEGURIDAD EN REDES/proyecto/clave3.txt", "w+");

        fwrite(temp1, sizeof(char), sizeof(temp1), fp1);
        fwrite(temp2, sizeof(char), sizeof(temp2), fp2);
        fwrite(temp3, sizeof(char), sizeof(temp3), fp3);

        rewind(fp1);
        rewind(fp2);
        rewind(fp3);

        for (int i = 0; i < sizeof(key1); i++)
        {
            key1[i] = fgetc(fp1);
        }
        for (int i = 0; i < sizeof(key2); i++)
        {
            key2[i] = fgetc(fp2);
        }
        for (int i = 0; i < sizeof(key3); i++)
        {
            key3[i] = fgetc(fp3);
        }

        fclose(fp1);
        fclose(fp2);
        fclose(fp3);

        SALTO
        system("PAUSE");
        printf("Clave1: ");
        for (int i = 0; i < sizeof(key1); i++)
            printf("%d ", (unsigned int)key1[i]);
        SALTO
        printf("Clave2: ");
        for (int i = 0; i < sizeof(key2); i++)
            printf("%d ", (unsigned int)key2[i]);
        SALTO
        printf("Clave3: ");
        for (int i = 0; i < sizeof(key3); i++)
            printf("%d ", (unsigned int)key3[i]);
        SALTO
        system("PAUSE");
        //1MB
        SALTO
        printf("Archivo de 1MB: ");
        SALTO
        printf("Encriptando archivo...");
        encrypt("C:/Users/jplop/Documents/Tercer semestre/SEGURIDAD EN REDES/proyecto/encriptado1.txt", "C:/Users/jplop/Documents/Tercer semestre/SEGURIDAD EN REDES/proyecto/1MB.txt", key1);
        SALTO
        printf("Archivo encriptado...");
        SALTO
        system("PAUSE");
        printf("Desencriptando archivo...");
        decrypt("C:/Users/jplop/Documents/Tercer semestre/SEGURIDAD EN REDES/proyecto/desencriptado1.txt", "C:/Users/jplop/Documents/Tercer semestre/SEGURIDAD EN REDES/proyecto/encriptado1.txt", key1);
        SALTO
        printf("Archivo desencriptado...");
        SALTO
        system("PAUSE");
        //10MB
        SALTO
        printf("Archivo de 10MB: ");
        SALTO
        printf("Encriptando archivo...");
        encrypt("C:/Users/jplop/Documents/Tercer semestre/SEGURIDAD EN REDES/proyecto/encriptado2.txt", "C:/Users/jplop/Documents/Tercer semestre/SEGURIDAD EN REDES/proyecto/10MB.txt", key2);
        SALTO
        printf("Archivo encriptado...");
        SALTO
        system("PAUSE");
        printf("Desencriptando archivo...");
        decrypt("C:/Users/jplop/Documents/Tercer semestre/SEGURIDAD EN REDES/proyecto/desencriptado2.txt", "C:/Users/jplop/Documents/Tercer semestre/SEGURIDAD EN REDES/proyecto/encriptado2.txt", key2);
        SALTO
        printf("Archivo desencriptado...");
        SALTO
        system("PAUSE");
        //100MB
        SALTO
        printf("Archivo de 100MB: ");
        SALTO
        printf("Encriptando archivo...");
        encrypt("C:/Users/jplop/Documents/Tercer semestre/SEGURIDAD EN REDES/proyecto/encriptado3.txt", "C:/Users/jplop/Documents/Tercer semestre/SEGURIDAD EN REDES/proyecto/100MB.txt", key3);
        SALTO
        printf("Archivo encriptado...");
        SALTO
        system("PAUSE");
        printf("Desencriptando archivo...");
        decrypt("C:/Users/jplop/Documents/Tercer semestre/SEGURIDAD EN REDES/proyecto/desencriptado3.txt", "C:/Users/jplop/Documents/Tercer semestre/SEGURIDAD EN REDES/proyecto/encriptado3.txt", key3);
        SALTO
        printf("Archivo desencriptado...");
        SALTO
        system("PAUSE");

        std::fstream fs;
        std::string str;
        fs.open("C:/Users/jplop/Documents/Tercer semestre/SEGURIDAD EN REDES/proyecto/1MB.txt", std::fstream::in);
        fs >> str;
        char* temp = new char[crypto_sign_BYTES+str.length() + 1];
        std::strcpy(temp, str.c_str());

        unsigned long long message_len = str.length();
        unsigned long long signed_message_len;
        
        unsigned char* message = new unsigned char[crypto_sign_BYTES + str.length() + 1];

        unsigned char* signed_message_f = new unsigned char[crypto_sign_BYTES + str.length() + 1];

        message = (unsigned char*)temp;

        crypto_sign(signed_message_f, &signed_message_len,
            message, message_len, sk);

        unsigned char* unsigned_message = new unsigned char[crypto_sign_BYTES + str.length() + 1];

        unsigned long long unsigned_message_len;
        if (crypto_sign_open(unsigned_message, &unsigned_message_len,
            signed_message_f, signed_message_len, pk) != 0) {
            printf("Invalido");
        }
        else
        {
            printf("Valido");
        }
        delete[] message;
        delete[] temp;
        delete[] signed_message_f;
        return 0;
}
