using System;
using System.Text;
using System.Threading.Tasks;
using EasyTotp;
using NUnit.Framework;

namespace EasyTotpTest
{
    [TestFixture]
    public class TotpTest
    {
        private const string Key = "12345678901234567890123456789012"; //32 chars 
        private readonly byte[] _aesKey = Encoding.UTF8.GetBytes("12345678901234567890123456789012");
        private readonly byte[] _aesIv = Encoding.UTF8.GetBytes("1234567890123456");
        

        [Test]
        public async Task SameTotpTheSameTimeStepEncrypted()
        {
            while(true)
            {
                if(DateTime.Now.Second%5==0) break;
                await Task.Delay(800);
            }

            var totp = new Totp()
                    .Secret(Key)
                    .Length(8)
                    .ValidFor(TimeSpan.FromSeconds(5))
                    .UseDefaultEncryptor(_aesKey,_aesIv);

            var value1 = totp.ComputeEncrypted();
            
            var value1Dec= totp.Decrypt(value1);

            await Task.Delay(3000);

            var value2 = totp.ComputeEncrypted();
            var value2Dec= totp.Decrypt(value2);

            Assert.AreEqual(value1Dec, value2Dec);
        }

        [Test]
        public async Task NotSameTotp_OutOfTimeStep_Encrypted()
        {
            while(true){
                if(DateTime.Now.Second%5==0) break;
                await Task.Delay(800);
            }

            var totp = new Totp()
                    .Secret(Key)
                    .Length(8)
                    .ValidFor(TimeSpan.FromSeconds(5))
                    .UseDefaultEncryptor(_aesKey,_aesIv);

            var value1 = totp.ComputeEncrypted();
            var value1Dec= totp.Decrypt(value1);

            await Task.Delay(6000);

            var value2 = totp.ComputeEncrypted();
            var value2Dec= totp.Decrypt(value2);

            Assert.AreNotEqual(value1Dec, value2Dec);
        }
        [Test]
        public async Task SameTotpTheSameTimeStep()
        {

            while(true){
                if(DateTime.Now.Second%5==0) break;
                await Task.Delay(800);
            }

            var totp = new Totp()
                    .Secret(Key)
                    .Length(8)
                    .ValidFor(TimeSpan.FromSeconds(5));

            var value1 = totp.Compute();

            await Task.Delay(2000);

            var value2 = totp.Compute();

            Assert.AreEqual(value1, value2);
        }

        [Test]
        public async Task NotSameTotp_OutOfTimeStep()
        {
            while(true){
                if(DateTime.Now.Second%5==0) break;
                await Task.Delay(800);
            }
            var totp = new Totp()
                    .Secret(Key)
                    .Length(8)
                    .ValidFor(TimeSpan.FromSeconds(5));

            var value1 = totp.Compute();

            await Task.Delay(6000);

            var value2 = totp.Compute();

            Assert.AreNotEqual(value1, value2);
        }
    }
}