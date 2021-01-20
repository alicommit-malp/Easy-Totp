namespace EasyTotp{
    /// <summary>
    /// To be used for user's provided encryption algorithm
    /// </summary>
    public interface IEncryptor
    {
        /// <summary>
        /// Encrypt the given <paramref name="plainText"></paramref>
        /// </summary>
        /// <param name="plainText">the string which must be encrypted</param>
        /// <returns>the encrypted byte[] of the <paramref name="plainText"/></returns>
        byte[] Encrypt(string plainText);
        
        /// <summary>
        /// Decrypt the given <paramref name="cipherText"></paramref>
        /// </summary>
        /// <param name="cipherText">the encrypted byte array</param>
        /// <returns>the decrypted value of the <paramref name="cipherText"></paramref></returns>
        string Decrypt(byte[] cipherText);   
    }
}