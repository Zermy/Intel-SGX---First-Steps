// Step_Test.cpp : Diese Datei enthält die Funktion "main". Hier beginnt und endet die Ausführung des Programms.
//
#include "pch.h"
#include <iostream>
#include <Windows.h>
#include "sgx_urts.h"
#include "sgx_tcrypto.h"
#include "Test_Step_u.h"

#define MAX_BUF_LEN 100
# define ENCLAVE_FILENAME "Test_Step.signed.dll"
int main(int argc, char* argv[])
{
	sgx_enclave_id_t   eid;
	sgx_status_t       ret = SGX_SUCCESS;
	sgx_launch_token_t token = { 0 };
	int updated = 0;
	char* buffer = (char*)"Hello World!";

	if (argc > 1)
	{
		buffer = argv[1];
	}


	ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);

	if (ret != SGX_SUCCESS) {
		printf("\nApp: error %#x, failed to create enclave.\n", ret);
	}
	int res = -1;
	ret = init(eid, &res);
	if (ret != SGX_SUCCESS || res != SGX_SUCCESS) {
		std::cout << "App: failed while init" << ret << std::endl;
		std::cout << res << std::endl;
	}
	sgx_ec256_signature_t sig;
	ret = sign(eid, &res, buffer, strlen(buffer), (void*) &sig, sizeof(sig));
	if (ret != SGX_SUCCESS || res != SGX_SUCCESS) {
		std::cout << "App: failed while signature" << ret << std::endl;
	}
	else
	{
		std::cout << "Signature for message: " << buffer << std::endl << sig.x << sig.y << std::endl;
	}
	

	ret = verify(eid, &res, buffer, strlen(buffer), (void*)&sig, sizeof(sig));
	if (ret != SGX_SUCCESS || res != SGX_EC_VALID) {
		std::cout << "App: failed while verfying´: " <<  ret << std::endl;
		std::cout << "Signature status: " << res << std::endl;
	}
	else
	{
		std::cout << "Signature for message: " << buffer << " successfull verified!" << std::endl;
	}
	
	getchar();
}

// Programm ausführen: STRG+F5 oder "Debuggen" > Menü "Ohne Debuggen starten"
// Programm debuggen: F5 oder "Debuggen" > Menü "Debuggen starten"

// Tipps für den Einstieg: 
//   1. Verwenden Sie das Projektmappen-Explorer-Fenster zum Hinzufügen/Verwalten von Dateien.
//   2. Verwenden Sie das Team Explorer-Fenster zum Herstellen einer Verbindung mit der Quellcodeverwaltung.
//   3. Verwenden Sie das Ausgabefenster, um die Buildausgabe und andere Nachrichten anzuzeigen.
//   4. Verwenden Sie das Fenster "Fehlerliste", um Fehler anzuzeigen.
//   5. Wechseln Sie zu "Projekt" > "Neues Element hinzufügen", um neue Codedateien zu erstellen, bzw. zu "Projekt" > "Vorhandenes Element hinzufügen", um dem Projekt vorhandene Codedateien hinzuzufügen.
//   6. Um dieses Projekt später erneut zu öffnen, wechseln Sie zu "Datei" > "Öffnen" > "Projekt", und wählen Sie die SLN-Datei aus.
