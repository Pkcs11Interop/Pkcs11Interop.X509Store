/*
 *  Copyright 2017-2024 The Pkcs11Interop Project
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
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

namespace Net.Pkcs11Interop.X509Store.Tests.SoftHsm2
{
    public static class SoftHsm2Manager
    {
        #region Token1

        public const string Token1Label = "First token";

        public const string Token1SoPin = "1111111111";

        public const string Token1UserPin = "11111111";

        public const string Token1TestCaLabel = "Token1TestCa";

        public const string Token1TestUserRsaLabel = "Token1TestUserRsa";

        public const string Token1TestUserEcdsaLabel = "Token1TestUserEcdsa";

        #endregion

        #region Token2

        public const string Token2Label = "Second token";

        public const string Token2SoPin = "2222222222";

        public const string Token2UserPin = "22222222";

        public const string Token2TestCaLabel = "Token2TestCa";

        public const string Token2TestUserRsaLabel = "Token2TestUserRsa";

        public const string Token2TestUserEcdsaLabel = "Token2TestUserEcdsa";

        #endregion

        #region Token3

        public const string Token3Label = "Third token";

        public const string Token3SoPin = "3333333333";

        public const string Token3UserPin = "33333333";

        public const string Token3TestCaLabel = "Token3TestCa";

        public const string Token3TestUserRsaLabel = "Token3TestUserRsa";

        public const string Token3TestUserEcdsaLabel = "Token3TestUserEcdsa";

        #endregion

        private static string _libraryPath = null;

        public static string LibraryPath
        {
            get
            {
                return _libraryPath;
            }
        }

        private static IPinProvider _pinProvider = null;

        public static IPinProvider PinProvider
        {
            get
            {
                if (_pinProvider == null)
                    _pinProvider = new SoftHsm2PinProvider();

                return _pinProvider;
            }
        }

        static SoftHsm2Manager()
        {
            // Determine base path
            string basePath = Helpers.GetBasePath();

            // Create directory for SoftHSM2 tokens
            string tokensDir = Path.Combine(basePath, "SoftHsm2", "tokens");
            if (!Directory.Exists(tokensDir))
                Directory.CreateDirectory(tokensDir);

            // Determine path of configuration file
            string configPath = Path.Combine(basePath, "SoftHsm2", "softhsm2.conf");

            // Update contents of configuration file
            string configContent = File.ReadAllText(configPath);
            configContent = configContent.Replace("__TOKENDIR__", tokensDir);
            File.WriteAllText(configPath, configContent);

            // Setup environment variable with path to configuration file
            EnvironmentHelper.SetEnvironmentVariable("SOFTHSM2_CONF", configPath);

            // Determine path to PKCS#11 library
            if (Platform.IsWindows)
            {
                if (Platform.Uses64BitRuntime)
                    _libraryPath = Path.Combine(basePath, "SoftHsm2", "windows", "softhsm2-x64.dll");
                else
                    _libraryPath = Path.Combine(basePath, "SoftHsm2", "windows", "softhsm2.dll");
            }
            else if (Platform.IsLinux)
            {
                if (Platform.Uses64BitRuntime)
                    _libraryPath = Path.Combine(basePath, "SoftHsm2", "linux", "libsofthsm2.so");
                else
                    throw new UnsupportedPlatformException("Pkcs11Interop.X509Store.Tests cannot be run on 32-bit Linux");
            }
            else if (Platform.IsMacOsX)
            {
                if (Platform.Uses64BitRuntime)
                    _libraryPath = Path.Combine(basePath, "SoftHsm2", "osx", "libsofthsm2.so");
                else
                    throw new UnsupportedPlatformException("Pkcs11Interop.X509Store.Tests cannot be run on 32-bit macOS");
            }
            else
            {
                throw new UnsupportedPlatformException("Pkcs11Interop.X509Store.Tests cannot be run on this platform");
            }

            // Set up a custom DllImportResolver that may be needed on some Linux distributions
            SetupCustomDllImportResolver();

            InitializeTokens();
        }

        /// <summary>
        /// Sets up a custom DllImportResolver that may be needed when Pkcs11Interop is running on Linux with .NET 5 or later
        /// </summary>
        static void SetupCustomDllImportResolver()
        {
#if NET5_0_OR_GREATER
            if (Platform.IsLinux)
            {
                // Pkcs11Interop uses native functions from "libdl.so", but Ubuntu 22.04 and possibly also other distros have "libdl.so.2".
                // Therefore, we need to set up a DllImportResolver to remap "libdl" to "libdl.so.2".
                NativeLibrary.SetDllImportResolver(typeof(Pkcs11InteropFactories).Assembly, (libraryName, assembly, dllImportSearchPath) =>
                {
                    if (libraryName == "libdl")
                    {
                        // Note: This mapping might need to be modified if your distribution uses a different version of libdl.
                        return NativeLibrary.Load("libdl.so.2", assembly, dllImportSearchPath);
                    }
                    else
                    {
                        return NativeLibrary.Load(libraryName, assembly, dllImportSearchPath);
                    }
                });
            }
#endif
        }

        private static void InitializeTokens()
        {
            Pkcs11InteropFactories factories = new Pkcs11InteropFactories();

            // Initialize tokens and import objects
            using (IPkcs11Library pkcs11Library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, LibraryPath, AppType.MultiThreaded))
            {
                // Initialize first token
                List<ISlot> slots = pkcs11Library.GetSlotList(SlotsType.WithOrWithoutTokenPresent);
                if (slots.Count != 1)
                    return; // Already initialized
                else
                    InitializeToken(slots[0], Token1Label, Token1SoPin, Token1UserPin);

                // Initialize second token
                slots = pkcs11Library.GetSlotList(SlotsType.WithOrWithoutTokenPresent);
                if (slots.Count != 2)
                    throw new Exception("Unexpected number of slots");
                else
                    InitializeToken(slots[1], Token2Label, Token2SoPin, Token2UserPin);

                // Initialize third token
                slots = pkcs11Library.GetSlotList(SlotsType.WithOrWithoutTokenPresent);
                if (slots.Count != 3)
                    throw new Exception("Unexpected number of slots");
                else
                    InitializeToken(slots[2], Token3Label, Token3SoPin, Token3UserPin);

                // Import objects to first token
                using (ISession session = slots[0].OpenSession(SessionType.ReadWrite))
                {
                    session.Login(CKU.CKU_USER, Token1UserPin);

                    // Import CA cert without private key
                    session.CreateObject(CryptoObjects.GetTestCaCertAttributes(session, Token1TestCaLabel));

                    // Import user cert with RSA private and public keys
                    session.CreateObject(CryptoObjects.GetTestUserRsaCertAttributes(session, Token1TestUserRsaLabel));
                    session.CreateObject(CryptoObjects.GetTestUserRsaPrivKeyAttributes(session, Token1TestUserRsaLabel, "PrivKey", false));
                    session.CreateObject(CryptoObjects.GetTestUserRsaPubKeyAttributes(session, Token1TestUserRsaLabel, "PubKey"));

                    // Import user cert with ECDSA private and public keys
                    session.CreateObject(CryptoObjects.GetTestUserEcdsaCertAttributes(session, Token1TestUserEcdsaLabel));
                    session.CreateObject(CryptoObjects.GetTestUserEcdsaPrivKeyAttributes(session, Token1TestUserEcdsaLabel, "PrivKey", false));
                    session.CreateObject(CryptoObjects.GetTestUserEcdsaPubKeyAttributes(session, Token1TestUserEcdsaLabel, "PubKey"));
                }

                // Import objects to second token
                using (ISession session = slots[1].OpenSession(SessionType.ReadWrite))
                {
                    session.Login(CKU.CKU_USER, Token2UserPin);

                    // Import CA cert without private key
                    session.CreateObject(CryptoObjects.GetTestCaCertAttributes(session, Token1TestCaLabel));

                    // Import user cert with RSA private and public keys
                    session.CreateObject(CryptoObjects.GetTestUserRsaCertAttributes(session, Token2TestUserRsaLabel));
                    session.CreateObject(CryptoObjects.GetTestUserRsaPrivKeyAttributes(session, Token2TestUserRsaLabel, "PrivKey", true));
                    session.CreateObject(CryptoObjects.GetTestUserRsaPubKeyAttributes(session, Token2TestUserRsaLabel, "PubKey"));

                    // Import user cert with ECDSA private and public keys
                    session.CreateObject(CryptoObjects.GetTestUserEcdsaCertAttributes(session, Token2TestUserEcdsaLabel));
                    session.CreateObject(CryptoObjects.GetTestUserEcdsaPrivKeyAttributes(session, Token2TestUserEcdsaLabel, "PrivKey", true));
                    session.CreateObject(CryptoObjects.GetTestUserEcdsaPubKeyAttributes(session, Token2TestUserEcdsaLabel, "PubKey"));
                }

                // Import objects to third token
                using (ISession session = slots[2].OpenSession(SessionType.ReadWrite))
                {
                    session.Login(CKU.CKU_USER, Token3UserPin);

                    // Import CA cert without private key
                    session.CreateObject(CryptoObjects.GetTestCaCertAttributes(session, Token3TestCaLabel));

                    // Import user cert with RSA private key only
                    session.CreateObject(CryptoObjects.GetTestUserRsaCertAttributes(session, Token3TestUserRsaLabel));
                    session.CreateObject(CryptoObjects.GetTestUserRsaPrivKeyAttributes(session, Token3TestUserRsaLabel, "PrivKey", true));

                    // Import user cert with ECDSA private key only
                    session.CreateObject(CryptoObjects.GetTestUserEcdsaCertAttributes(session, Token3TestUserEcdsaLabel));
                    session.CreateObject(CryptoObjects.GetTestUserEcdsaPrivKeyAttributes(session, Token3TestUserEcdsaLabel, "PrivKey", true));
                }
            }
        }

        private static void InitializeToken(ISlot slot, string label, string soPin, string userPin)
        {
            if (slot.GetTokenInfo().TokenFlags.TokenInitialized)
                throw new Exception("Token already initialized");

            slot.InitToken(soPin, label);
            using (ISession session = slot.OpenSession(SessionType.ReadWrite))
            {
                session.Login(CKU.CKU_SO, soPin);
                session.InitPin(userPin);
            }
        }
    }
}
