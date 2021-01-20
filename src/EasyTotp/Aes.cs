using System;
using System.IO;
using System.Security.Cryptography;

namespace EasyTotp
{
    /// <summary>
    /// Default encryption implementation <see cref="IEncryptor"/> <seealso cref="System.Security.Cryptography.Aes"/>
    /// </summary>
    internal class Aes :IEncryptor
    {
        private readonly byte[] _key;
        private readonly byte[] _iv;

        public Aes(byte[] key, byte[] iv)
        {
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException(nameof(key));
            _key = key;

            if (iv == null || iv.Length <= 0)
                throw new ArgumentNullException(nameof(iv));
            _iv = iv;
        }

        /// <inheritdoc/> 
        public byte[] Encrypt(string plainText)
        {
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException(nameof(plainText));

            // Create an Aes object with the specified key and IV.
            using var aesAlg = System.Security.Cryptography.Aes.Create();
            aesAlg.Key = _key;
            aesAlg.IV = _iv;

            // Create a decrytor to perform the stream transform.
            var encryptor = aesAlg.CreateEncryptor(aesAlg.Key,
                aesAlg.IV);

            // Create the streams used for encryption.
            using var msEncrypt = new MemoryStream();
            using var csEncrypt = new CryptoStream(msEncrypt,
                encryptor,
                CryptoStreamMode.Write);
            using (var swEncrypt = new StreamWriter(csEncrypt))
            {
                //Write all data to the stream.
                swEncrypt.Write(plainText);
            }

            var encrypted = msEncrypt.ToArray();


            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }

        /// <inheritdoc/> 
        public string Decrypt(byte[] cipherText)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException(nameof(cipherText));

            // Declare the string used to hold
            // the decrypted text.

            // Create an Aes object with the specified key and IV.
            using var aesAlg = System.Security.Cryptography.Aes.Create();
            aesAlg.Key = _key;
            aesAlg.IV = _iv;

            // Create a decrytor to perform the stream transform.
            var decryptor = aesAlg.CreateDecryptor(aesAlg.Key,
                aesAlg.IV);

            // Create the streams used for decryption.
            using var msDecrypt = new MemoryStream(cipherText);
            using var csDecrypt = new CryptoStream(msDecrypt,
                decryptor,
                CryptoStreamMode.Read);
            using var srDecrypt = new StreamReader(csDecrypt);
            // Read the decrypted bytes from the decrypting stream
            // and place them in a string.
            var plaintext = srDecrypt.ReadToEnd();

            return plaintext;
        }
    }
}