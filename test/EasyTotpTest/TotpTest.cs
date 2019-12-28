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
        public async Task Test1_Enc()
        {
            var totp = new Totp(Encoding.UTF8.GetBytes(Key), 5, 8);

            var value1 = totp.ComputeEncrypted(_aesKey,_aesIv);
            TestContext.WriteLine($"Value1: {value1} at {DateTime.Now}");

            await Task.Delay(4000);

            var value2 = totp.ComputeEncrypted(_aesKey,_aesIv);
            TestContext.WriteLine($"Value1: {value2} at {DateTime.Now}");

            Assert.AreEqual(value1, value2);
        }

        [Test]
        public async Task Test2_Enc()
        {
            var totp = new Totp(Encoding.UTF8.GetBytes(Key), 5, 8);

            var value1 = totp.ComputeEncrypted(_aesKey,_aesIv);
            TestContext.WriteLine($"Value1: {value1} at {DateTime.Now}");

            await Task.Delay(6000);

            var value2 = totp.ComputeEncrypted(_aesKey,_aesIv);
            TestContext.WriteLine($"Value1: {value2} at {DateTime.Now}");

            Assert.AreNotEqual(value1, value2);
        }
        [Test]
        public async Task Test1()
        {
            var totp = new Totp(Encoding.UTF8.GetBytes(Key), 5, 8);

            var value1 = totp.Compute();
            TestContext.WriteLine($"Value1: {value1} at {DateTime.Now}");

            await Task.Delay(4000);

            var value2 = totp.Compute();
            TestContext.WriteLine($"Value1: {value2} at {DateTime.Now}");

            Assert.AreEqual(value1, value2);
        }

        [Test]
        public async Task Test2()
        {
            var totp = new Totp(Encoding.UTF8.GetBytes(Key), 5, 8);

            var value1 = totp.Compute();
            TestContext.WriteLine($"Value1: {value1} at {DateTime.Now}");

            await Task.Delay(6000);

            var value2 = totp.Compute();
            TestContext.WriteLine($"Value1: {value2} at {DateTime.Now}");

            Assert.AreNotEqual(value1, value2);
        }
    }
}