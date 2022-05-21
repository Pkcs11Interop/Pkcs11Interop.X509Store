/*
 *  Copyright 2017-2022 The Pkcs11Interop Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 *  Written for the Pkcs11Interop project by:
 *  Jaroslav IMRICH <jimrich@jimrich.sk>
 */

namespace Net.Pkcs11Interop.X509Store
{
    /// <summary>
    /// Interface for provider of PIN codes for PKCS#11 tokens and keys
    /// </summary>
    public interface IPinProvider
    {
        /// <summary>
        /// Requests PIN code for PKCS#11 token
        /// </summary>
        /// <param name="storeInfo">Detailed information about PKCS#11 based X.509 store</param>
        /// <param name="slotInfo">Detailed information about PKCS#11 slot representing a logical reader that potentially contains a token</param>
        /// <param name="tokenInfo">Detailed information about PKCS#11 token (cryptographic device) that is typically present in the slot</param>
        /// <returns>Result for PIN request with instructions on how to perform login</returns>
        GetPinResult GetTokenPin(Pkcs11X509StoreInfo storeInfo, Pkcs11SlotInfo slotInfo, Pkcs11TokenInfo tokenInfo);

        /// <summary>
        /// Requests PIN code for private key stored on PKCS#11 token
        /// </summary>
        /// <param name="storeInfo">Detailed information about PKCS#11 based X.509 store</param>
        /// <param name="slotInfo">Detailed information about PKCS#11 slot representing a logical reader that potentially contains a token</param>
        /// <param name="tokenInfo">Detailed information about PKCS#11 token (cryptographic device) that is typically present in the slot</param>
        /// <param name="certificateInfo">Detailed information about X.509 certificate stored on PKCS#11 token</param>
        /// <returns>Result for PIN request with instructions on how to perform login</returns>
        GetPinResult GetKeyPin(Pkcs11X509StoreInfo storeInfo, Pkcs11SlotInfo slotInfo, Pkcs11TokenInfo tokenInfo, Pkcs11X509CertificateInfo certificateInfo);
    }
}
