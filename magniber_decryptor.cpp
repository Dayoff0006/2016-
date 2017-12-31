/*
 * This tool will decrypt files encrypted by the Magniber ransomware with
 * AES128 ( CBC mode ) algorithm.
 *
 * RE and report by MalwareBytes ( @hasherezade )
 *
 *  https://blog.malwarebytes.com/threat-analysis/2017/10/magniber-ransomware-exclusively-for-south-koreans/
 *
 * Decryptor written by Simone 'evilsocket' Margaritelli
 *  
 *  https://www.evilsocket.net/
 *  evilsocket at protonmail dot com
 */
#include <stdio.h>
#include <tchar.h>
#include <Windows.h>
#include <wincrypt.h>
#include <string>

#pragma comment(lib, "crypt32.lib")

#define DEFAULT_IV      "EP866p5M93wDS513"
#define DEFAULT_KEY     "S25943n9Gt099y4K"
#define REQ_IV_KEY_SIZE 16
#define CHUNK_SIZE      128

typedef struct {
	std::string iv;
	std::string key;
	std::string input;
	std::string output;
}
ARGS;

typedef struct {
	BLOBHEADER hdr;
	DWORD dwKeySize;
	BYTE key[16];
} 
KEY_BLOB;

void usage(char *argvz) {
	printf("\nUsage: %s /key KEY /iv IV /input INPUT_FILENAME /output OUTPUT_FILENAME\n", argvz);
}

int main(int argc, char **argv)
{
	printf("Magniber AES128 Decryptor\n");
	printf(" by Simone 'evilsocket' Margaritelli\n");
	printf(" evilsocket at protonmail dot com\n\n" );

	ARGS args = {
		DEFAULT_IV,
		DEFAULT_KEY,
		"",
		""
	};

	HCRYPTPROV hProv = NULL;
	HCRYPTKEY hKey = NULL;
	DWORD dwMode = CRYPT_MODE_CBC,
		dwPadding = 0;
	KEY_BLOB kblob = { 0 };
	BOOL bSuccess = FALSE;
	HANDLE hInputFile = NULL,
		hOutputFile = NULL;
	BYTE chunk[CHUNK_SIZE] = { 0 };
	DWORD read = 0;
	DWORD written = 0;
	BOOL bFinal = FALSE;

	for( int i = 1; i < argc; ++i ) {
		if (!strcmp(argv[i], "/key") && i < argc) {
			args.key = argv[i + 1];
			++i;
		}
		else if (!strcmp(argv[i], "/iv") && i < argc) {
			args.iv = argv[i + 1];
			++i;
		}
		else if (!strcmp(argv[i], "/input") && i < argc) {
			args.input = argv[i + 1];
			++i;
		}
		else if (!strcmp(argv[i], "/output") && i < argc) {
			args.output = argv[i + 1];
			++i;
		} 
		else {
			usage(argv[0]);
			return 1;
		}
	}

	if (args.iv.size() != REQ_IV_KEY_SIZE) {
		printf("Unpexpected IV length of %d, required %d characters.\n", args.iv.size(), REQ_IV_KEY_SIZE);
		goto done;
	} 
	else if (args.key.size() != REQ_IV_KEY_SIZE) {
		printf("Unpexpected KEY length of %d, required %d characters.\n", args.key.size(), REQ_IV_KEY_SIZE);
		goto done;
	}
	else if (args.input.empty()) {
		printf("No input file specified!\n");
		usage(argv[0]);
		goto done;
	}
	else if (args.output.empty()) {
		printf("No output file specified!\n");
		usage(argv[0]);
		goto done;
	}

	bSuccess = CryptAcquireContext( &hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_NEWKEYSET | CRYPT_VERIFYCONTEXT);
	if(!bSuccess){
		printf( "Error 0x%08x while acquiring context.\n", GetLastError() );
		goto done;
	}

	kblob.hdr.bType = PLAINTEXTKEYBLOB;
	kblob.hdr.bVersion = CUR_BLOB_VERSION;
	kblob.hdr.reserved = 0;
	kblob.hdr.aiKeyAlg = CALG_AES_128;
	kblob.dwKeySize = args.key.size();
	memcpy(kblob.key, args.key.c_str(), kblob.dwKeySize);

	bSuccess = CryptImportKey(hProv, (const BYTE *)&kblob, sizeof(KEY_BLOB), 0, 0, &hKey);
	if(!bSuccess){
		printf("Error 0x%08x while importing the AES key\n", GetLastError());
		goto done;
	}

	bSuccess = CryptSetKeyParam( hKey, KP_MODE, (BYTE *)&dwMode, 0);
	if (!bSuccess) {
		printf("Error 0x%08x while setting CBC mode.\n", GetLastError());
		goto done;
	}

	bSuccess = CryptSetKeyParam(hKey, KP_IV, (BYTE *)args.iv.c_str(), 0);
	if (!bSuccess) {
		printf("Error 0x%08x while setting IV.\n", GetLastError());
		return 1;
	}
	
	hInputFile = CreateFileA( args.input.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	hOutputFile = CreateFileA( args.output.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hInputFile == INVALID_HANDLE_VALUE) {
		printf("Error 0x%08x while opening %s for reading.\n", GetLastError(), args.input.c_str());
		goto done;
	}
	else if (hOutputFile == INVALID_HANDLE_VALUE) {
		printf("Error 0x%08x while opening %s for writing.\n", GetLastError(), args.output.c_str());
		goto done;
	}

	// First 16 bytes are the ID/IV and should match what the user provided.
	bSuccess = ReadFile(hInputFile, chunk, REQ_IV_KEY_SIZE, &read, NULL);
	if (!bSuccess || read != REQ_IV_KEY_SIZE) {
		printf("Error 0x%08x while reading first 16 bytes of IV.\n", GetLastError());
		goto done;
	}
	else if (memcmp(chunk, args.iv.c_str(), REQ_IV_KEY_SIZE)) {
		printf("Unexpected IV '%s' found in file while provided IV is '%s', Magniber version mismatch.\n", chunk, args.iv.c_str() );
		goto done;
	}

	printf("Decrypting file ...\n");

	do {
		bSuccess = ReadFile(hInputFile, chunk, CHUNK_SIZE, &read, NULL);
		if (!bSuccess || !read) {
			break;
		}

		bFinal = read < CHUNK_SIZE;
		if (!CryptDecrypt(hKey, NULL, bFinal, 0, chunk, &read)) {
			printf("Error 0x%08x while decrypting chunk.\n", GetLastError());
			break;
		}
		
		if (!WriteFile(hOutputFile, chunk, read, &written, NULL)) {
			printf("Error 0x%08x while writing to file.\n", GetLastError());
			break;
		}
		
		ZeroMemory(chunk, CHUNK_SIZE);
	}
	while (!bFinal);

	printf("Done!\n");

done:

	if (hInputFile && hInputFile != INVALID_HANDLE_VALUE)
		CloseHandle(hInputFile);
	
	if (hOutputFile && hOutputFile != INVALID_HANDLE_VALUE)
		CloseHandle(hOutputFile);

	if (hKey)
		CryptDestroyKey(hKey);

	if (hProv)
		CryptReleaseContext(hProv, 0);

    return 0;
}
