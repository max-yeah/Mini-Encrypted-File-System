#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <sys/stat.h>
#include <unistd.h>
#include<cstdlib>
#include <string.h>

using namespace std;

// This function will create public/private key pairs under /publickeys folder and /privatekeys folder
// keyfile's naming convension: username_randomnumber_publickey and username_randomnumber_privatekey
// Example: Admin_2018509453_privatekey
void create_RSA(string key_name) {
    size_t pos = key_name.find("_");
    string username = key_name.substr(0,pos);

    if (username == "Admin") {

        string publickey_path = "./publickeys/" + key_name + "_publickey";
        string privatekey_path = "./privatekeys/" + key_name + "_privatekey";
        
        RSA   *rsa = NULL;
        FILE  *fp  = NULL;
        FILE  *fp1  = NULL;

        BIGNUM *bne = NULL;
        bne = BN_new();
        BN_set_word(bne, 59);

        RSA *keypair = NULL;
        keypair = RSA_new();
        RSA_generate_key_ex(keypair, 2048, bne, NULL);

        //generate public key and store to local
        fp = fopen(&publickey_path[0], "w");
        PEM_write_RSAPublicKey(fp, keypair);
        fclose(fp);
        
        //generate private key and store to local
        fp1 = fopen(&privatekey_path[0], "w");
        PEM_write_RSAPrivateKey(fp1, keypair, NULL, NULL, 0, NULL, NULL);
        fclose(fp1);
    } else {
        // ... should implement when doing adduser function
    }

}

// This function will read RSA (public or private) keys specified by key_path
RSA * read_RSAkey(string key_type, string key_path){
    
    FILE  *fp  = NULL;
    RSA   *rsa = NULL;

    fp = fopen(&key_path[0], "rb");
    if (fp == NULL){
        //invalid key_name provided
        return rsa;
    }

    if (key_type == "public"){
        PEM_read_RSAPublicKey(fp, &rsa, NULL, NULL);
        fclose(fp);        
    } else if (key_type == "private"){
        PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL);
        fclose(fp);
    }
    return rsa;
}

//This function implement RSA public key encryption
int public_encrypt(int flen, unsigned char* from, unsigned char* to, RSA* key, int padding) {
    
    int result = RSA_public_encrypt(flen, from, to, key, padding);
    return result;
}

//This function implement RSA private key decryption
int private_decrypt(int flen, unsigned char* from, unsigned char* to, RSA* key, int padding) {

    int result = RSA_private_decrypt(flen, from, to, key, padding);
    return result;
}

// Adopted from other people's code. Might be useful but not in use yet.
// void create_encrypted_file(char* encrypted, RSA* key_pair) {

//     FILE* encrypted_file = fopen("encrypted_file.bin", "w");
//     fwrite(encrypted, sizeof(*encrypted), RSA_size(key_pair), encrypted_file);
//     fclose(encrypted_file);
// }

int initial_folder_setup(){
    //create "filesystem", "privatekeys","publickeys" folders
        int status1 = mkdir("filesystem", 0777);
        int status2 = mkdir("privatekeys", 0777);
        int status3 = mkdir("publickeys", 0777);

        if (status1 == 0 && status2 == 0 && status3 == 0){
            cout << "Filesystem created successfully" << endl << endl;
            return 0;
        } else {
            cerr << "Failed to create filesystem. Please check permission and try again " << endl;
            return 1;
        }
}

void initial_adminkey_setup(){

    // Providing a seed value
	srand((unsigned) time(NULL));
	// Get a random number
	int random = rand() % 9999999999;

    string username = "Admin";
    string key_name = username + "_" + to_string(random);

    create_RSA(key_name);
    cout << "Admin Public/Private key pair has been created." << endl;
    cout << "Your private key_name is " << key_name << endl;
    cout << "Please store your key_name safely. Admin can login by command: " << endl;
    cout << "./fileserver " << key_name << endl << endl;
}

int login_authentication(string key_name){
    RSA *private_key;
    RSA *public_key;
    string public_key_path, private_key_path, username;
    
    public_key_path = "./publickeys/" + key_name + "_publickey";
    public_key = read_RSAkey("public", public_key_path);
    
    size_t pos = key_name.find("_");
    username = key_name.substr(0,pos);

    if (username == "Admin"){
        private_key_path = "./privatekeys/" + key_name + "_privatekey";
    } else {
        private_key_path = "./filesystem/" + username + "/" + key_name + "_privatekey";
    }
    private_key = read_RSAkey("private", private_key_path);
    
    if (public_key == NULL || private_key == NULL){
        //not such key by searching the provided key_name
        // cout << "Invalid key_name is provided. Fileserver closed." << endl;
        return 1;
    } else {
        // Successfully read public key and private key. Now User authentication
        // We uses private key to decrypt a message that was encrypted with the corresponding public key.
        // If the decryption is successful, the user is authenticated and can proceed with the session.

        char message[] = "My secret";
        char *encrypt = NULL;
        char *decrypt = NULL;

        // Do RSA encryption using public key
        encrypt = (char*)malloc(RSA_size(public_key));
        int encrypt_length = public_encrypt(strlen(message) + 1, (unsigned char*)message, (unsigned char*)encrypt, public_key, RSA_PKCS1_OAEP_PADDING);
        if(encrypt_length == -1) {
            // cout << "An error occurred in public_encrypt() method" << endl;
            return 1;
        }
        
        // Try to do RSA decryption using corresponding private key
        decrypt = (char *)malloc(encrypt_length);
        int decrypt_length = private_decrypt(encrypt_length, (unsigned char*)encrypt, (unsigned char*)decrypt, private_key, RSA_PKCS1_OAEP_PADDING);
        if(decrypt_length == -1) {
            // cout << "An error occurred in private_decrypt() method" << endl;
            return 1;
        }
        if (strcmp(decrypt, message) == 0){
            // cout << "Successfully login" << endl;
            // cout << decrypt << endl;
            return 0;
        } else {
            return 1;
        }
    }
}

void command_pwd(){
    
}


int main(int argc, char** argv) {

    string username, user_command, key_name;

    if (argc != 2) {
        cout << "Wrong command to start the fileserver. You should use command: " << endl;
        cout << "./fileserver key_name" << endl;
        return 1;
    }

    cout << "--------------------------------------------------------" << endl;
    cout << "     You are accessing Encrypted Secure File System     " << endl;
    cout << "--------------------------------------------------------" << endl << endl;

    struct stat st, st1, st2;
    if (stat("filesystem", &st) == -1 && stat("privatekeys", &st1) == -1 && stat("publickeys", &st2) == -1)
    {
        //Initial Setup
        cout << "No file system exists yet. Execute Initial setup..." << endl << endl;

        int folder_result = initial_folder_setup();
        if (folder_result == 1) {return 1;}

        initial_adminkey_setup();

        cout << "Initial setup finshed, Fileserver closed. Admin now can login using the admin keyfile" << endl;
        return 0;

    } else if (stat("filesystem", &st) == -1 || stat("privatekeys", &st1) == -1 || stat("publickeys", &st2) == -1){
            cout << "Partial file system exist. Please remove folder filesystem/privatekeys/publickeys and try again." << endl;
            return 1;
    } else {
        // cout << "Directory already exists" << endl;
        // Time to do user authentication

        key_name = argv[1];
        int login_result = login_authentication(key_name);
        if (login_result == 1){
            cout << "Invalid key_name is provided. Fileserver closed." << endl;
            return 1;
        } else {
            size_t pos = key_name.find("_");
            username = key_name.substr(0,pos);
            cout << "Welcome! Logged in as " << username << endl;
        }
    }

    /* ....Implement fileserver different commands...... */
    
    while (true){
        cout << endl;
        cout << "> ";
        getline(cin,user_command);
        // cout << "User input: " << user_command << endl;

        if (user_command == "exit") {
            cout << "Fileserver closed. Goodbye " << username << " :)" << endl;
            return 0;
        }

        /* Directory commands */
        // 1. pwd 
        //
        // else if (user_command == "pwd") {
        //     command_pwd(...);
        // }

        // 2. cd  
        //
        // else if (user_command ....) {

        // }

        // 3. ls  
        //
        // else if (user_command ....) {

        // }

        // 4. mkdir  
        //
        // else if (user_command ....) {

        // }


        /* File commands section*/
        // 5. cat 
        //
        // else if (user_command ....) {
            // command_cat(...);
        // }

        // 6. share 
        //
        // else if (user_command ....) {

        // }

        // 7. mkfile 
        //
        // else if (user_command ....) {

        // }

        /* Admin specific feature */
        // 8. adduser 
        //
        // else if (user_command ....) {

        // }


        else {
            cout << "Invalid command." << endl;
        }

    }

    
}

