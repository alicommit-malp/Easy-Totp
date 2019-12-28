namespace EasyTotp
{
    public interface ITotp
    {
        string Compute();
        byte[] ComputeEncrypted(byte[] key,byte[] iv);
        string Decrypt(byte[] cipherTest, byte[] key, byte[] iv);
        int GetRemainingSeconds();
    }
}