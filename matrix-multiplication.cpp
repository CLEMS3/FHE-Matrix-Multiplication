#include "openfhe.h"
#include <iostream>
#include <vector>
#include <cmath>
#include <algorithm>
#include <numeric>

using namespace lbcrypto;
using namespace std;

void homomorphicMatrixMultiplication() {

    // Matrix dimensions (N x N)
    const uint32_t N = 2;
    vector<double> A_row1 = {1.0, 2.0};
    vector<double> A_row2 = {3.0, 4.0};
    vector<double> B_col1 = {5.0, 7.0};
    vector<double> B_col2 = {6.0, 8.0};
    vector<double> expected = {19.0, 22.0, 43.0, 50.0};


    // Setup CryptoContext
    uint32_t scaleModSize = 50;  
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(2);
    parameters.SetScalingModSize(scaleModSize);
    parameters.SetBatchSize(8);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    // Enable the features that you wish to use.
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);


    // Keys
    KeyPair keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalSumKeyGen(keys.secretKey); 

    // Generating keys for all generation shits
    vector<uint32_t> shifts(N - 1); 
    iota(shifts.begin(), shifts.end(), 1);
    cc->EvalAutomorphismKeyGen(keys.secretKey, shifts);

    // Encoding matrix
    Plaintext plaintextARow1 = cc->MakeCKKSPackedPlaintext(A_row1, scaleModSize, 0);
    Plaintext plaintextARow2 = cc->MakeCKKSPackedPlaintext(A_row2, scaleModSize, 0);
    Ciphertext<DCRTPoly> ciphertextARow1 = cc->Encrypt(keys.publicKey, plaintextARow1);
    Ciphertext<DCRTPoly> ciphertextARow2 = cc->Encrypt(keys.publicKey, plaintextARow2);
    uint32_t currentScaleSize = scaleModSize;
    size_t currentLevel = ciphertextARow1->GetLevel();

    Plaintext plaintextBCol1 = cc->MakeCKKSPackedPlaintext(B_col1, currentScaleSize, currentLevel);
    Plaintext plaintextBCol2 = cc->MakeCKKSPackedPlaintext(B_col2, currentScaleSize, currentLevel);
    Ciphertext<DCRTPoly> ciphertextBCol1 = cc->Encrypt(keys.publicKey, plaintextBCol1);
    Ciphertext<DCRTPoly> ciphertextBCol2 = cc->Encrypt(keys.publicKey, plaintextBCol2);


    // Matrix multiplication
    Ciphertext<DCRTPoly> ciphertextResult11 = cc->EvalInnerProduct(ciphertextARow1, ciphertextBCol1, N);
    Ciphertext<DCRTPoly> ciphertextResult12 = cc->EvalInnerProduct(ciphertextARow1, ciphertextBCol2, N);
    Ciphertext<DCRTPoly> ciphertextResult21 = cc->EvalInnerProduct(ciphertextARow2, ciphertextBCol1, N);
    Ciphertext<DCRTPoly> ciphertextResult22 = cc->EvalInnerProduct(ciphertextARow2, ciphertextBCol2, N);

    // Decrypting and verifying result
    Plaintext result;
    vector<Ciphertext<DCRTPoly>> ciphertextResult = {ciphertextResult11, ciphertextResult12, ciphertextResult21, ciphertextResult22};
    vector<string> labels = {"C[0][0]", "C[0][1]", "C[1][0]", "C[1][1]"};
    
    cout << "\nDecrypted Result Matrix C = A * B (Expected result: [[19, 22], [43, 50]]):" << endl;

    bool success = true;
    double value;
    double diff;
    for (size_t i = 0; i < ciphertextResult.size(); ++i) {
        cc->Decrypt(keys.secretKey, ciphertextResult[i], &result);
        value = result->GetCKKSPackedValue()[0].real();
        diff = abs(value - expected[i]);
        
        cout << "   " << labels[i] << " (Result): " << value << " | expected: " << expected[i] << " | Error: " << diff << endl;
        
        if (diff > 0.000001) { // Check tolerance of 1e-6
            success = false;
        }
    }
    if (success){
        cout << "\nFully Homomorphic Matrix Multiplication Completed successfully." << endl;
        cout << "Whoopee! Bad guys won't be able to steal my precious numbers 😊" << endl;
    } else{
        // This should not be displayed anyway
        cout << "\nFully Homomorphic Matrix Multiplication Completed, failing to get expected result. This can be due to unsufficient accuracy or wrong calculations" << endl;
        cout << "🥺😢" << endl;
    }
}

int main() {
    try {
        homomorphicMatrixMultiplication();
    } catch (const exception& e) {
        cerr << "An exception occurred: " << e.what() << endl;
        return 1;
    }
    return 0;
}