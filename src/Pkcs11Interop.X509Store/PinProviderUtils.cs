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

using System;

namespace Net.Pkcs11Interop.X509Store
{
    /// <summary>
    /// Utility class for calling provider of PIN codes for PKCS#11 tokens and keys
    /// </summary>
    internal static class PinProviderUtils
    {
        /// <summary>
        /// Requests PIN code for PKCS#11 token
        /// </summary>
        /// <param name="tokenContext">Internal context for Pkcs11Token class</param>
        /// <returns>PIN code</returns>
        public static byte[] GetTokenPin(Pkcs11TokenContext tokenContext)
        {
            IPinProvider pinProvider = tokenContext.SlotContext.StoreContext.PinProvider;

            Pkcs11X509StoreInfo storeInfo = tokenContext.SlotContext.StoreContext.StoreInfo;
            Pkcs11SlotInfo slotInfo = tokenContext.SlotContext.SlotInfo;
            Pkcs11TokenInfo tokenInfo = tokenContext.TokenInfo;

            GetPinResult getPinResult = pinProvider.GetTokenPin(storeInfo, slotInfo, tokenInfo);
            if (getPinResult == null)
                throw new Exception("Invalid response from IPinProvider");

            if (getPinResult.Cancel)
                throw new LoginCancelledException("Login with token pin was cancelled");

            return getPinResult.Pin;
        }

        /// <summary>
        /// Requests PIN code for private key stored on PKCS#11 token
        /// </summary>
        /// <param name="certificateContext">Internal context for Pkcs11X509Certificate2 class</param>
        /// <returns>PIN code</returns>
        public static byte[] GetKeyPin(Pkcs11X509CertificateContext certificateContext)
        {
            IPinProvider pinProvider = certificateContext.TokenContext.SlotContext.StoreContext.PinProvider;

            Pkcs11X509StoreInfo storeInfo = certificateContext.TokenContext.SlotContext.StoreContext.StoreInfo;
            Pkcs11SlotInfo slotInfo = certificateContext.TokenContext.SlotContext.SlotInfo;
            Pkcs11TokenInfo tokenInfo = certificateContext.TokenContext.TokenInfo;
            Pkcs11X509CertificateInfo certificateInfo = certificateContext.CertificateInfo;

            GetPinResult getPinResult = pinProvider.GetKeyPin(storeInfo, slotInfo, tokenInfo, certificateInfo);
            if (getPinResult == null)
                throw new Exception("Invalid response from IPinProvider");

            if (getPinResult.Cancel)
                throw new LoginCancelledException("Login with key pin was cancelled");

            return getPinResult.Pin;
        }
    }
}
