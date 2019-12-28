namespace EasyTotp
{
    public interface ITotp
    {
        string Compute();
        byte[] ComputeEncrypted(byte[] key,byte[] iv);
        int GetRemainingSeconds();
    }
}