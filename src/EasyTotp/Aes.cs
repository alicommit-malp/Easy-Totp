using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;

namespace EasyTotp
{
    public class Aes
    {
        private readonly byte[] _key;
        private readonly byte[] _iv;

        public Aes(byte[] key, byte[] iv)
        {
            if (_key == null || _key.Length <= 0)
                throw new ArgumentNullException(nameof(_key));
            _key = key;

            if (_iv == null || _iv.Length <= 0)
                throw new ArgumentNullException(nameof(_iv));
            _iv = iv;
        }

        public byte[] Encrypt(string plainText)
        {
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException(nameof(plainText));
            byte[] encrypted;

            // Create an Aes object
            // with the specified key and IV.
            using (var aesAlg = System.Security.Cryptography.Aes.Create())
            {
                Debug.Assert(aesAlg != null, nameof(aesAlg) + " != null");
                aesAlg.Key = _key;
                aesAlg.IV = _iv;

                var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using var msEncrypt = new MemoryStream();
                using var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
                using var swEncrypt = new StreamWriter(csEncrypt);

                //Write all data to the stream.
                swEncrypt.Write(plainText);
                encrypted = msEncrypt.ToArray();
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }

        public string Decrypt(byte[] cipherText)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException(nameof(cipherText));

            // Declare the string used to hold
            // the decrypted text.
            string plaintext;

            // Create an Aes object
            // with the specified key and IV.
            using (var aesAlg = System.Security.Cryptography.Aes.Create())
            {
                Debug.Assert(aesAlg != null, nameof(aesAlg) + " != null");
                aesAlg.Key = _key;
                aesAlg.IV = _iv;

                // Create a decryptor to perform the stream transform.
                var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using var msDecrypt = new MemoryStream(cipherText);
                using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
                using var srDecrypt = new StreamReader(csDecrypt);
                // Read the decrypted bytes from the decrypting stream
                // and place them in a string.
                plaintext = srDecrypt.ReadToEnd();
            }

            return plaintext;
        }
    }
}