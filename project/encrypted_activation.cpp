#include "openfhe.h"
#include <iostream>
#include <vector>
#include <cmath>
#include <algorithm>
#include <iomanip>

using namespace lbcrypto;
using namespace std;

const double acceptable_error = 1e-3;

// Plaintext functions
double square_func(double x) {
    return x * x;
}

double poly_silu_approx(double x) {
    return 0.5 * x + 0.25 * x * x - (1.0/48.0) * pow(x, 4);
}

int main() {
    try {
        // setup cryptocontext and keys and features
        uint32_t multDepth = 6; 
        uint32_t scaleModSize = 50;
        uint32_t batchSize = 1;

        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(multDepth);
        parameters.SetScalingModSize(scaleModSize);
        parameters.SetBatchSize(batchSize);

        CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);

        cout << "CKKS Scheme Initialized for Part B" << endl;

        KeyPair keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);

        // We reuse logic from Part A to get the inputs for Part B
        vector<vector<double>> X = {{1.0, 2.0, 3.0}, {4.0, 5.0, 6.0}, {7.0, 8.0, 9.0}};
        vector<vector<double>> K = {{1.0, 0.0}, {0.0, 1.0}};
        
        vector<vector<Ciphertext<DCRTPoly>>> encryptedX(3, vector<Ciphertext<DCRTPoly>>(3));
        for (int i = 0; i < 3; i++) {
            for (int j = 0; j < 3; j++) {
                encryptedX[i][j] = cc->Encrypt(keys.publicKey, cc->MakeCKKSPackedPlaintext({X[i][j]}, scaleModSize, 0));
            }
        }

        vector<vector<Ciphertext<DCRTPoly>>> convolutionOutput(2, vector<Ciphertext<DCRTPoly>>(2));
        cout << "Computing Part A Convolution to get inputs..." << endl;
        for (int i = 0; i < 2; i++) {
            for (int j = 0; j < 2; j++) {
                Ciphertext<DCRTPoly> sum;
                bool first = true;
                for (int m = 0; m < 2; m++) {
                    for (int n = 0; n < 2; n++) {
                         Ciphertext<DCRTPoly> prod = cc->EvalMult(encryptedX[i+m][j+n], K[m][n]);
                         if (first) { sum = prod; first = false; }
                         else { sum = cc->EvalAdd(sum, prod); }
                    }
                }
                convolutionOutput[i][j] = sum;
            }
        }
        
        // Expected convolution result (for verification)
        vector<vector<double>> expectedConv = {{6.0, 8.0}, {12.0, 14.0}};

        // Apply both functions to each element of convolutionOutput
        
        bool success = true;

        cout << "\nChecking Square Function f1(x) = x^2:" << endl;
        for(int i=0; i<2; i++){
            for(int j=0; j<2; j++){
                 // Homomorphic Square
                 Ciphertext<DCRTPoly> x = convolutionOutput[i][j];
                 Ciphertext<DCRTPoly> x2 = cc->EvalMult(x, x);
                 
                 // Decrypt
                 Plaintext result;
                 cc->Decrypt(keys.secretKey, x2, &result);
                 result->SetLength(1);
                 double val = result->GetCKKSPackedValue()[0].real();
                 double expected = square_func(expectedConv[i][j]);
                 
                 cout << "Input: " << expectedConv[i][j] << " | x^2 Result: " << val << " | Expected: " << expected;
                 if (abs(val - expected) > acceptable_error) {
                     cout << " [FAIL]";
                     success = false;
                 } else {
                     cout << " [PASS]";
                 }
                 cout << endl;
            }
        }

        cout << "\nChecking Polynomial SiLU f2(x) = 0.5x + 0.25x^2 - (1/48)x^4:" << endl;
        for(int i=0; i<2; i++){
            for(int j=0; j<2; j++){
                 Ciphertext<DCRTPoly> x = convolutionOutput[i][j];
                 
                 // Compute powers
                 Ciphertext<DCRTPoly> x2 = cc->EvalMult(x, x);
                 Ciphertext<DCRTPoly> x4 = cc->EvalMult(x2, x2);

                 // Compute terms
                 Ciphertext<DCRTPoly> term1 = cc->EvalMult(x, 0.5);
                 Ciphertext<DCRTPoly> term2 = cc->EvalMult(x2, 0.25);
                 Ciphertext<DCRTPoly> term3 = cc->EvalMult(x4, -1.0/48.0);
                 
                 // Sum
                 Ciphertext<DCRTPoly> res = cc->EvalAdd(term1, term2);
                 res = cc->EvalAdd(res, term3);

                 // Decrypt
                 Plaintext result;
                 cc->Decrypt(keys.secretKey, res, &result);
                 result->SetLength(1);
                 double val = result->GetCKKSPackedValue()[0].real();
                 double expected = poly_silu_approx(expectedConv[i][j]);

                 cout << "Input: " << expectedConv[i][j] << " | SiLU Result: " << val << " | Expected: " << expected;
                 if (abs(val - expected) > acceptable_error) {
                     cout << " [FAIL]";
                     success = false;
                 } else {
                     cout << " [PASS]";
                 }
                 cout << endl;
            }
        }

        if (success) {
            cout << "\nPart B: Encrypted Non-Linear Functions Completed successfully." << endl;
        } else {
            cout << "\nPart B: FAILED verification." << endl;
        }

    } catch (const exception& e) {
        cerr << "Exception: " << e.what() << endl;
        return 1;
    }

    return 0;
}
