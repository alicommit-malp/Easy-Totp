using System;
using System.Security.Cryptography;
using System.Text;

namespace EasyTotp
{
    /// <summary>
    /// Time based One-Time password generator 
    /// </summary>
    public class Totp 
    {
        private const long UnixEpochTicks = 621355968000000000L;
        private const long TicksToSeconds = 10000000L;
        private  int _step;
        private  int _totpSize;
        private byte[] _key;
        private  IEncryptor _encryptor;

        
        /// <summary>
        /// Using the default encryptor <see cref="Aes"/> 
        /// </summary>
        /// <param name="key">The string key which will be used to encrypt</param>
        /// <param name="iv">The string iv which will be used to encrypt</param>
        /// <returns>new instance of the <see cref="Totp"/></returns>
        public Totp UseDefaultEncryptor(string key, string iv){
            _encryptor = new Aes(Encoding.UTF8.GetBytes(key),Encoding.UTF8.GetBytes(iv));
            return this;
        }

        /// <summary>
        /// Using the default encryptor <see cref="Aes"/> 
        /// </summary>
        /// <param name="key">The byte[] key which will be used to encrypt</param>
        /// <param name="iv">The byte[] iv which will be used to encrypt</param>
        /// <returns>new instance of the <see cref="Totp"/></returns>
        public Totp UseDefaultEncryptor(byte[] key, byte[] iv){
            _encryptor = new Aes(key,iv);
            return this;
        }

        /// <summary>
        /// Provide user defined encryptor <see cref="IEncryptor"/>
        /// </summary>
        /// <param name="encryptor"><see cref="IEncryptor"/></param>
        /// <returns>instance of <see cref="Totp"/></returns>
        public Totp Use(IEncryptor encryptor){
            _encryptor = encryptor;
            return this;
        }

        /// <summary>
        /// Provide the lenght of the generated TOTP
        /// </summary>
        /// <param name="length"></param>
        /// <returns>instance of the <see cref="Totp"/></returns>
        public Totp Length(int length){
            _totpSize = length;
            return this;
        }

        /// <summary>
        /// Set for how long the generated key 
        /// </summary>
        /// <param name="timeSpan">the timespan which the generated totp will be valid</param>
        /// <returns>instance of the <see cref="Totp"/></returns>
        public Totp ValidFor(TimeSpan timeSpan){
            _step = timeSpan.Seconds;
            return this;
        }

        /// <summary>
        /// Provide the key for the encryption if its not provided by the constructor
        /// </summary>
        /// <param name="key">string key</param>
        /// <returns>instance of the <see cref="Totp"/></returns>
        public Totp Secret(string key){
            _key=Encoding.UTF8.GetBytes(key);
            return this;
        }
        
        /// <summary>
        /// Provide the key for the encryption if its not provided by the constructor
        /// </summary>
        /// <param name="secret">byte[] key</param>
        /// <returns>instance of the <see cref="Totp"/></returns>
        public Totp Secret(byte[] secret){
            _key=secret;
            return this;
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

        /// <summary>
        /// Compute encrypted version of the TOTP
        /// </summary>
        /// <returns>byte[] representing the encrypted totp</returns>
        public byte[] ComputeEncrypted()
        {
            var totp = Compute();
            return _encryptor.Encrypt(totp);
        }

        /// <summary>
        /// Get the remaining milliseconds until the expiration of the current epoch
        /// <remarks>when you instantiate <see cref="Totp"/> every some seconds the key will be different
        /// this method will tell the caller how long later the key will be renewed
        /// </remarks>
        /// </summary>
        /// <returns></returns>
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

        /// <summary>
        /// Decrypt an encrypted <see cref="Totp"/> by <seealso cref="IEncryptor"/> implementation
        /// </summary>
        /// <param name="cipherTest">the encrypted text</param>
        /// <returns>un-encrypted version of the provided <paramref name="cipherTest"/></returns>
        public string Decrypt(byte[] cipherTest)
        {
           return _encryptor.Decrypt(cipherTest); 
        }
    }
}