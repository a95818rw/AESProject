#include<stdio.h>
#include<stdlib.h>

void printBytes(unsigned char b[], int len) {   //print出明文，密文或金鑰。
  int i;
  for (i=0; i<len; i++)
    printf("%d ", b[i]);
  printf("\n");
}

unsigned char AES_Sbox[] = {99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,
    118,202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,183,253,
    147,38,54,63,247,204,52,165,229,241,113,216,49,21,4,199,35,195,24,150,5,154,
    7,18,128,226,235,39,178,117,9,131,44,26,27,110,90,160,82,59,214,179,41,227,
    47,132,83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,208,239,170,
    251,67,77,51,133,69,249,2,127,80,60,159,168,81,163,64,143,146,157,56,245,
    188,182,218,33,16,255,243,210,205,12,19,236,95,151,68,23,196,167,126,61,
    100,93,25,115,96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219,224,
    50,58,10,73,6,36,92,194,211,172,98,145,149,228,121,231,200,55,109,141,213,
    78,169,108,86,244,234,101,122,174,8,186,120,37,46,28,166,180,198,232,221,
    116,31,75,189,139,138,112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,
    158,225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223,140,161,
    137,13,191,230,66,104,65,153,45,15,176,84,187,22};  //SBOX

unsigned char xtime[256];//shift and mod 0x1b


void expansionKey(unsigned char key[], int keyLen){ //金鑰位置，金鑰長度
        
        int i, j, rcon = 1, keyround = 16*(keyLen / 4 + 7); //keyround:16->11*16 24->13*16 32->15*16
        unsigned char arrayL[4], arrayChange[4];    //後面的陣列，轉換過的陣列。

        printf("鑰匙長度：%d\n",keyround);  //16->176 24->208 32->240

        for(i = keyLen; i < keyround; i += 4){
            memcpy(arrayL, &key[i-4], 4);

            if(i % keyLen == 0){
                arrayChange[0] = AES_Sbox[arrayL[1]]^rcon;
                arrayChange[1] = AES_Sbox[arrayL[2]];
                arrayChange[2] = AES_Sbox[arrayL[3]];
                arrayChange[3] = AES_Sbox[arrayL[0]];
                memcpy(arrayL, arrayChange, 4);
                if((rcon <<= 1) >= 256)
                    rcon ^= 0x11b;  

            }

            else if((keyLen == 32) && (i % keyLen == 16)){  //AES-256專用
                arrayChange[0] = AES_Sbox[arrayL[0]];
                arrayChange[1] = AES_Sbox[arrayL[1]];
                arrayChange[2] = AES_Sbox[arrayL[2]];
                arrayChange[3] = AES_Sbox[arrayL[3]];
                memcpy(arrayL, arrayChange, 4);
            }

            for(j = 0; j < 4; j++){
                key[i + j] = key[i + j - keyLen] ^ arrayL[j];
            }

        }

    }

//-------------------------------round開始------------------------------------//

void byteSub(unsigned char text[]){
    int i;
    for(i = 0;  i < 16; i++)
        text[i] = AES_Sbox[text[i]];
}   //s_box轉換

void shiftRow(unsigned char text[]){
    int i, j, k;
    unsigned char copytext[16];
    memcpy(copytext, text, 16);
    for(i = 0; i < 16; i += 4){ //一列一列來
            
        text[i] = copytext [i];
        text[i + 1] = copytext [(i + 5) % 16];
        text[i + 2] = copytext [(i + 10) % 16];
        text[i + 3] = copytext [(i + 15) % 16];

        //(j + 4 - i) % 4 轉換到的位置copyText[(列 + 4 - 行) % 4]
        //ex:X(0,0)->X(0,0); X(1,0)->X(1,3); X(2,0)->X(2,2);
    }
}

void mixColumn(unsigned char text[]){

    unsigned char t0, t1, t2, t3;
    unsigned char x;
    int i;
    for(i = 0; i < 16; i += 4){ //shift後餘除0x1b
        t0 = text[i];
        t1 = text[i + 1];
        t2 = text[i + 2];
        t3 = text[i + 3];
        x = t0 ^ t1 ^ t2 ^ t3;
        text[i] ^= x ^ xtime[t0 ^ t1];
        text[i + 1] ^= x ^ xtime[t1 ^ t2];
        text[i + 2] ^= x ^ xtime[t2 ^ t3];
        text[i + 3] ^= x ^ xtime[t3 ^ t0];
    }

}

void addRoundKey(unsigned char text[], unsigned char key[], int roundTime){ //roundTime 第幾次round
    int i;
    for(i = 0; i < 16; i++)
        text[i] ^= key[i + roundTime * 16];
}

void round(unsigned char text[], unsigned char key[], int roundTime){
    byteSub(text);
    shiftRow(text);
    mixColumn(text);
    addRoundKey(text, key, roundTime);
}

int main(){
    
    unsigned char plain_text[16];
    unsigned char key[16 * (14 + 1)];
    int keyLen;
    int i;
    for(i = 0; i < 16; i++)
        plain_text[i] = 0x11 * i;   //建立明文
    for(i = 0; i < 32; i++)
        key[i] = i;     //建立金鑰
    keyLen = 24;    //金鑰長度
    int keyMaxLen = keyLen * 4 + 112;   //金鑰最大長度

    expansionKey(key, keyLen);
    printf("原始金鑰："); printBytes(key, keyLen);
    printf("展開金鑰："); printBytes(key, keyMaxLen); //金鑰擴展結束
//-------------------------------round開始------------------------------------//
    for(i = 0; i < 128; i++) {
        xtime[i] = i << 1;
        xtime[128 + i] = (i << 1) ^ 0x1b;
    }//建立xtime表

    int roundTime;
    int roundMaxTime = keyLen / 4 + 6;  //keyLen:16->10 24->12 32->14

    addRoundKey(plain_text, key, 0);
    for(roundTime = 1; roundTime < roundMaxTime; roundTime++){
        round(plain_text, key, roundTime);
    }
    byteSub(plain_text);
    shiftRow(plain_text);
    addRoundKey(plain_text, key, roundTime);
    
    printf("加密完後："); printBytes(plain_text, 16);

}