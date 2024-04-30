#include <iostream>
#include <cstring>
#include <fstream>
#include <vector>


int streamEncryptDecrypt(char* inputFile, char* outputFile, char* keyFile, char* mode){
    std::ifstream key;
    std::ifstream input;
    std::ofstream output;
    char inputChar;
    char keyChar;
    char xorByte;
    key.open(keyFile, std::ios::binary);
    input.open(inputFile, std::ios::binary);
    output.open(outputFile, std::ios::binary | std::ios::trunc);
    
    while(input.get(inputChar)){
        if(!key.get(keyChar)){
            key.clear();
            key.seekg(0, std::ios::beg);
            key.get(keyChar);
        }
        xorByte = inputChar ^ keyChar;
        output.write(&xorByte, 1);
    }
    return 0;
}

int blockDecrypt(std::ifstream& key, char* keyBuffer, std::ostream& output, std::vector<char> encryptBuffer, char* buffer, int start, int end, int* keyIndex){
    /*
    Function: Dencrypts encrypted text from input file and writes to output file. Will XOR bytes read in from input and key file. 
    Return: 0 if successful, 1 if unsuccessful
    */
    char xorByte;
    char temp;

    while(start != end){
        if(*keyIndex == 16){
            *keyIndex = 0;
        }
        int ascii = keyBuffer[*keyIndex];
        ascii = ascii % 2;
        if(ascii == 1){
            temp = buffer[end];
            buffer[end] = buffer[start];
            buffer[start] = temp;
            start++;
            if(start == end){
                (*keyIndex)++;
                break;
            }
            end--;
            (*keyIndex)++;
        }else{
            start++;
            (*keyIndex)++;
        }
    }

    for(int i = 0; i < 16; i++){
        if(static_cast<int>(buffer[i]) == 10){
            xorByte = 10 ^ keyBuffer[i];
            encryptBuffer.push_back(xorByte);
        }else{
            xorByte = buffer[i] ^ keyBuffer[i];
            encryptBuffer.push_back(xorByte);
        }
    }
    for(int i = 0; i < 16; i++){
        if(encryptBuffer[i] < 0){
            encryptBuffer.pop_back();
        }
    }
    output.write(encryptBuffer.data(), encryptBuffer.size());
    return 0;
}


int blockEncrypt(std::ifstream& key, char* keyBuffer, std::ostream& output, std::vector<char> encryptBuffer, char* buffer, int start, int end, int* keyIndex){
    /*
    Function: Encrypts ASCII text from input file and writes to output file. Will XOR bytes read in from input and key file. 
    Return: 0 if successful, 1 if unsuccessful
    */
    char xorByte;
    char temp;

    for(int i = 0; i < 16; i++){
        key.read(keyBuffer, 16);
        if(static_cast<int>(buffer[i]) == 10){
            xorByte = 10 ^ keyBuffer[i];
            encryptBuffer.push_back(xorByte);
        }else{
            xorByte = buffer[i] ^ keyBuffer[i];
            encryptBuffer.push_back(xorByte);
        }
    }
    while(start != end){
        if(*keyIndex == 16){
            *keyIndex = 0;
        }
        int ascii = keyBuffer[*keyIndex];
        ascii = ascii % 2;
        if(ascii == 1){
            temp = encryptBuffer[end];
            encryptBuffer[end] = encryptBuffer[start];
            encryptBuffer[start] = temp;
            start++;
            if(start == end){
                (*keyIndex)++;
                break;
            }
            end--;
            (*keyIndex)++;
        }else{
            start++;
            (*keyIndex)++;
        }
    }
    output.write(encryptBuffer.data(), 16);
    return 0;
}


int blockCipher(char* inputFile, char* outputFile, char* keyFile, char* mode){
    /*
    Function: Performs block cipher decryption and encryption on input file and appends to output file.
    Arguments: Input File, Output File, Key File, and Mode of operation
    Return: Return 0 if successful, return 1 if not successful
    */

    char buffer[16];
    char keyBuffer[16];
    int numBytes;
    int keyIndex = 0;
    std::vector<char> encryptBuffer;
    
    // Opens input file, key file, and output file
    std::ifstream input;
    std::ifstream key;
    std::ofstream output;

    input.open(inputFile, std::ios::binary);
    key.open(keyFile, std::ios::binary);

    try{
        if(input){
            if(key){
                output.open(outputFile, std::ios::binary | std::ios::trunc);
                key.read(keyBuffer,16);

                /*
                Will read in 16 bytes from input file and then call blockEncrypt function or blockDecrypt 
                based on mode of operation given
                */
               if(strcmp(mode,"E") == 0){
                    while(input.read(buffer,16)){
                        blockEncrypt(key, keyBuffer, output, encryptBuffer, buffer, 0, 15, &keyIndex);
                        keyIndex = 0;
                    }

                    keyIndex = 0;
                    numBytes = input.gcount();
                    for(int i = numBytes; i < 16; i++){
                            buffer[i] = 0x81;
                        }
                    blockEncrypt(key, keyBuffer, output, encryptBuffer, buffer, 0, 15, &keyIndex);
                    output.close();
                    input.close();
                    key.close();
               }else if(strcmp(mode, "D") == 0){
                    while(input.read(buffer,16)){
                        blockDecrypt(key, keyBuffer, output, encryptBuffer, buffer, 0, 15, &keyIndex);
                        keyIndex = 0;
                    }
                    output.close();
                    input.close();
                    key.close();
               }

            }else{
                throw std::invalid_argument("Key File Does Not Exist");
            }
        }else{
            throw std::invalid_argument("Input File Does Not Exist");
        }
    }
    catch(std::invalid_argument& e){
        std::cerr << e.what() << std::endl;
        return 1;
    }

    return 0;
}


int main(int argc, char* argv[]){
    /*
    Function: Will take in 5 arguments to decrypt and encrypt contents of a file
    Arguments: Function type(Block or Stream), Input file, Output file, Key file, and Mode of operation(Decrypt or encrypt)
    Return: 0 if successful, 1 if unsuccessful
    */

    if(argc != 6){
        return 1;
    }

    // Will error check cipher type and mode of operation
    try{
        if(strcmp(argv[5],"E") == 0 || strcmp(argv[5],"D") == 0){
            if(strcmp(argv[1],"B") == 0){
                int blockReturn = blockCipher(argv[2], argv[3], argv[4],argv[5]);
                if(blockReturn == 1){
                    return 1;
                }
            }else if(strcmp(argv[1],"S") == 0){
                int streamReturn = streamEncryptDecrypt(argv[2],argv[3], argv[4], argv[5]);
                if(streamReturn == 1){
                    return 1;
                }
                
            }else{
                throw std::invalid_argument("Invalid Function Type");
            }
        }else{
            throw std::invalid_argument("Invalid Mode Type");
        }
    }

    catch(std::invalid_argument& e){
        std::cerr << e.what() << std::endl;
        return 1;
    }

    return 0;
}
