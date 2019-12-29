namespace EasyTotp
{
    public interface ITotp
    {
        string Compute();
        byte[] ComputeEncrypted();
        string Decrypt(byte[] cipherTest);
        int GetRemainingSeconds();
    }
}