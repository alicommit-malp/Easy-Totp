namespace EasyTotp{
    public interface IEncryptor
    {
        byte[] Encrypt(string plainText);
        string Decrypt(byte[] cipherText);   
    }
}