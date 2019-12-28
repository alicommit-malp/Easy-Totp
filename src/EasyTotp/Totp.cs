using System;
using System.Security.Cryptography;
using System.Text;

namespace EasyTotp
{
    public class Totp :ITotp
    {
        private const long UnixEpochTicks = 621355968000000000L;
        private const long TicksToSeconds = 10000000L;
        private readonly int _step;
        private readonly int _totpSize;
        private readonly byte[] _key;

        
        /// <summary>
        /// Initialize the TOTP module
        /// </summary>
        /// <param name="secretKey">32 character secret</param>
        /// <param name="step">TOTP step size</param>
        /// <param name="outputSize">TOTP output digit length</param>
        public Totp(byte[] secretKey, int step, int outputSize)
        {
            _key = secretKey;
            _step = step;
            _totpSize = outputSize;
        }
        
        /// <summary>
        /// Compute the TOTP integer value 
        /// </summary>
        /// <returns>string representation of the TOTP digits</returns>
        public string Compute()
        {
            var window = CalculateTimeStepFromTimestamp(DateTime.UtcNow);

            var data = GetBigEndianBytes(window);

            var hmac = new HMACSHA1 {Key = _key};
            var hmacComputedHash = hmac.ComputeHash(data);

            var offset = hmacComputedHash[hmacComputedHash.Length - 1] & 0x0F;
            var otp = (hmacComputedHash[offset] & 0x7f) << 24
                      | (hmacComputedHash[offset + 1] & 0xff) << 16
                      | (hmacComputedHash[offset + 2] & 0xff) << 8
                      | (hmacComputedHash[offset + 3] & 0xff) % 1000000;

            var result = Digits(otp, _totpSize);

            return result;
        }

        public byte[] ComputeEncrypted(byte[] key, byte[] iv)
        {
            var aes = new Aes(key,iv);
            var totp = Compute();

            return aes.Encrypt(totp);
        }

        public int GetRemainingSeconds()
        {
            return _step - (int) (((DateTime.UtcNow.Ticks - UnixEpochTicks) / TicksToSeconds) % _step);
        }

        private static byte[] GetBigEndianBytes(long input)
        {
            // Since .net uses little endian numbers, we need to reverse the byte order to get big endian.
            var data = BitConverter.GetBytes(input);
            Array.Reverse(data);
            return data;
        }

        private long CalculateTimeStepFromTimestamp(DateTime timestamp)
        {
            var unixTimestamp = (timestamp.Ticks - UnixEpochTicks) / TicksToSeconds;
            var window = unixTimestamp / _step;
            return window;
        }

        private static string Digits(long input, int digitCount)
        {
            var truncatedValue = ((int) input % (int) Math.Pow(10, digitCount));
            return truncatedValue.ToString().PadLeft(digitCount, '0');
        }

        public string Decrypt(byte[] cipherTest, byte[] key, byte[] iv)
        {
           var aes = new Aes(key,iv);
           return aes.Decrypt(cipherTest); 
        }
    }
}