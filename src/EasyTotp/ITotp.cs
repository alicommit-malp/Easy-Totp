namespace EasyTotp
{
    public interface ITotp
    {
        string Compute();
        string ComputeEncrypted(byte[] key,byte[] iv);
        int GetRemainingSeconds();
    }
}