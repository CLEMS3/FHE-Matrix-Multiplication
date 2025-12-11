#include "openfhe.h"
#include <iostream>
#include <vector>
#include <cmath>
#include <algorithm>
#include <iomanip>

using namespace lbcrypto;
using namespace std;

// Tolerance for Part A
const double EPSILON = 1e-4;

int main() {
    try {
        // =================================================================================
        // 1. Setup CryptoContext
        // =================================================================================
        uint32_t multDepth = 2; // Need minimal depth for mul + add
        uint32_t scaleModSize = 50;
        uint32_t batchSize = 1; // We are treating each entry as a separate ciphertext for simplicity given "Encrypt each entry"

        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(multDepth);
        parameters.SetScalingModSize(scaleModSize);
        parameters.SetBatchSize(batchSize);

        CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);

        cout << "CKKS Scheme Initialized" << endl;

        // Key Generation
        KeyPair keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);
        // We might need EvalSum if we were packing, but here we just add ciphertexts, which is standard Add.

        // =================================================================================
        // 2. Input and Kernel
        // =================================================================================
        // Matrix X (3x3)
        // [ [1.0, 2.0, 3.0],
        //   [4.0, 5.0, 6.0],
        //   [7.0, 8.0, 9.0] ]
        vector<vector<double>> X = {
            {1.0, 2.0, 3.0},
            {4.0, 5.0, 6.0},
            {7.0, 8.0, 9.0}
        };

        // Kernel K (2x2)
        // [ [1.0, 0.0],
        //   [0.0, 1.0] ]
        vector<vector<double>> K = {
            {1.0, 0.0},
            {0.0, 1.0}
        };

        // Expected Result (2x2)
        // [ [ 6.0, 8.0],
        //   [12.0, 14.0] ]
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

        // =================================================================================
        // 3. Computation
        // =================================================================================
        cout << "Computing 2D Convolution..." << endl;
        // Output Y is 2x2
        vector<vector<Ciphertext<DCRTPoly>>> encryptedY(2, vector<Ciphertext<DCRTPoly>>(2));

        for (int i = 0; i < 2; i++) {
            for (int j = 0; j < 2; j++) {
                // Convolve K over window at (i,j)
                // Y[i][j] = sum(X[i+m][j+n] * K[m][n])
                Ciphertext<DCRTPoly> sum;
                bool first = true;

                for (int m = 0; m < 2; m++) {
                    for (int n = 0; n < 2; n++) {
                         // Element-wise multiply (Scalar mult since K is plaintext)
                         // We can multiply ciphertext by double directly or create plaintext for K element.
                         // Using MakeCKKSPackedPlaintext for K element is safer/standard.
                         
                         double kVal = K[m][n];
                         Ciphertext<DCRTPoly> prod;

                         // Optimization: If K is 0, product is 0. If K is 1, product is X.
                         // But we should do it properly for generic K.
                         if (abs(kVal) < 1e-9) {
                             // Treat as 0, skip adding if we want efficiently, but let's implement the generic math ops
                             // Actually, multiplying by 0 gives 0. 
                             // To keep levels consistent, we might just want to do the multiply.
                             // But adding a "zero" ciphertext is tricky if we don't have one handy at the right level.
                             // Let's just multiply.
                             prod = cc->EvalMult(encryptedX[i+m][j+n], kVal); 
                         } else {
                             prod = cc->EvalMult(encryptedX[i+m][j+n], kVal);
                         }

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

        // =================================================================================
        // 4. Verification
        // =================================================================================
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

                if (abs(val - expectedY[i][j]) > EPSILON) {
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
