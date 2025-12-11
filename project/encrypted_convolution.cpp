#include "openfhe.h"
#include <iostream>
#include <vector>
#include <cmath>
#include <algorithm>
#include <iomanip>

using namespace lbcrypto;
using namespace std;

const double acceptable_error = 1e-4;

int main() {
    try {
        // setup cryptocontext and keys and features
        uint32_t multDepth = 2;
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

        cout << "CKKS Scheme Initialized" << endl;

        KeyPair keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);
        // Inputs
        // Matrix X
        vector<vector<double>> X = {
            {1.0, 2.0, 3.0},
            {4.0, 5.0, 6.0},
            {7.0, 8.0, 9.0}
        };

        // Kernel K
        vector<vector<double>> K = {
            {1.0, 0.0},
            {0.0, 1.0}
        };

        // Expected Result (matrix Y)
        vector<vector<double>> expectedY = {
            {6.0, 8.0},
            {12.0, 14.0}
        };

        // Encrypt X
        cout << "Encrypting Matrix X..." << endl;
        vector<vector<Ciphertext<DCRTPoly>>> encryptedX(3, vector<Ciphertext<DCRTPoly>>(3));
        for (int i = 0; i < 3; i++) {
            for (int j = 0; j < 3; j++) {
                vector<double> val = {X[i][j]};
                Plaintext ptx = cc->MakeCKKSPackedPlaintext(val, scaleModSize, 0);
                encryptedX[i][j] = cc->Encrypt(keys.publicKey, ptx);
            }
        }

        // Computation of the convolution
        cout << "Computing 2D Convolution..." << endl;
        vector<vector<Ciphertext<DCRTPoly>>> encryptedY(2, vector<Ciphertext<DCRTPoly>>(2));

        for (int i = 0; i < 2; i++) {
            for (int j = 0; j < 2; j++) {
                Ciphertext<DCRTPoly> sum;
                bool first = true;

                for (int m = 0; m < 2; m++) {
                    for (int n = 0; n < 2; n++) {
                         // Element-wise multiplication
                         double kVal = K[m][n];
                         Ciphertext<DCRTPoly> prod;

                         prod = cc->EvalMult(encryptedX[i+m][j+n], kVal);

                         // Summation of the products
                         if (first) {
                             sum = prod;
                             first = false;
                         } else {
                             sum = cc->EvalAdd(sum, prod);
                         }
                    }
                }
                encryptedY[i][j] = sum;
            }
        }

        // Verification
        cout << "\nVerifying Results..." << endl;
        cout << "Expected Plaintext Result:" << endl;
        for(auto &row : expectedY) {
            cout << "[ ";
            for(auto val : row) cout << val << " ";
            cout << "]" << endl;
        }

        cout << "\nDecrypted Result:" << endl;
        bool success = true;
        for (int i = 0; i < 2; i++) {
            cout << "[ ";
            for (int j = 0; j < 2; j++) {
                Plaintext result;
                cc->Decrypt(keys.secretKey, encryptedY[i][j], &result);
                result->SetLength(1); // We only care about the first slot
                double val = result->GetCKKSPackedValue()[0].real();
                
                cout << val << " ";

                if (abs(val - expectedY[i][j]) > acceptable_error) {
                    success = false;
                    cerr << "\nError: Mismatch at (" << i << "," << j << "). "
                         << "Expected: " << expectedY[i][j] << ", Got: " << val << endl;
                }
            }
            cout << "]" << endl;
        }

        if (success) {
            cout << "\nPart A: Encrypted 2x2 Convolution Completed successfully." << endl;
        } else {
            cout << "\nPart A: FAILED verification." << endl;
        }

    } catch (const exception& e) {
        cerr << "Exception: " << e.what() << endl;
        return 1;
    }

    return 0;
}
