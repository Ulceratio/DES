using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CipherNamespace
{
    interface ICipher
    {
        byte[] Encryption(byte[] objToEncrypt);
        byte[] Decryption(byte[] objToEncrypt);
    }
}
