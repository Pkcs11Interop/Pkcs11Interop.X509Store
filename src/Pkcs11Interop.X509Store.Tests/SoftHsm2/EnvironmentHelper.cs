﻿/*
 *  Copyright 2017-2025 The Pkcs11Interop Project
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
using System.Runtime.InteropServices;
using Net.Pkcs11Interop.Common;

namespace Net.Pkcs11Interop.X509Store.Tests.SoftHsm2
{
    public static class EnvironmentHelper
    {
        private static class NativeMethods
        {
            [DllImport("libc")]
            internal static extern int setenv(string name, string value, int overwrite);
        }

        public static void SetEnvironmentVariable(string variable, string value)
        {
            if (Platform.IsWindows)
            {
                Environment.SetEnvironmentVariable(variable, value);
            }
            else
            {
                if (0 != NativeMethods.setenv(variable, value, 1))
                    throw new Exception("Unable to set environment variable");
            }
        }
    }
}
