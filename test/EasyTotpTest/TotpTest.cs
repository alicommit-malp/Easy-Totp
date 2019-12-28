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
        public void Test1_Enc()
        {
            while(true){
                if(DateTime.Now.Second%5==0) break;
                else Task.Delay(800).GetAwaiter().GetResult();
            }

            var totp = new Totp(Encoding.UTF8.GetBytes(Key), 5, 8);
            var aes = new Aes(_aesKey,_aesIv);

            TestContext.WriteLine(Encoding.UTF8.GetString(_aesIv));

            var value1 = totp.ComputeEncrypted(_aesKey,_aesIv);
            var value1Dec= aes.Decrypt(value1);
            TestContext.WriteLine($"Value1: {value1} Enc: {value1Dec} at {DateTime.Now}");

            Task.Delay(3000).GetAwaiter().GetResult();

            var value2 = totp.ComputeEncrypted(_aesKey,_aesIv);
            var value2Dec= aes.Decrypt(value2);
            TestContext.WriteLine($"Value2: {value2} Enc: {value2Dec} at {DateTime.Now}");

            Assert.AreEqual(value1Dec, value2Dec);
        }

        [Test]
        public  void Test2_Enc()
        {
            while(true){
                if(DateTime.Now.Second%5==0) break;
                else Task.Delay(800).GetAwaiter().GetResult();
            }

            var totp = new Totp(Encoding.UTF8.GetBytes(Key), 5, 8);
            var aes = new Aes(_aesKey,_aesIv);

            var value1 = totp.ComputeEncrypted(_aesKey,_aesIv);
            var value1Dec= aes.Decrypt(value1);
            TestContext.WriteLine($"Value1: {value1} Enc: {value1Dec} at {DateTime.Now}");

            Task.Delay(6000).GetAwaiter().GetResult();

            var value2 = totp.ComputeEncrypted(_aesKey,_aesIv);
            var value2Dec= aes.Decrypt(value2);
            TestContext.WriteLine($"Value2: {value2} Enc: {value2Dec} at {DateTime.Now}");

            Assert.AreNotEqual(value1Dec, value2Dec);
        }
        [Test]
        public void Test1()
        {

            while(true){
                if(DateTime.Now.Second%5==0) break;
                else Task.Delay(800).GetAwaiter().GetResult();
            }
            
            var totp = new Totp(Encoding.UTF8.GetBytes(Key), 5, 8);

            var value1 = totp.Compute();
            TestContext.WriteLine($"Value1: {value1} at {DateTime.Now}");

             Task.Delay(2000).GetAwaiter().GetResult();

            var value2 = totp.Compute();
            TestContext.WriteLine($"Value2: {value2} at {DateTime.Now}");

            Assert.AreEqual(value1, value2);
        }

        [Test]
        public void Test2()
        {
            while(true){
                if(DateTime.Now.Second%5==0) break;
                else Task.Delay(800).GetAwaiter().GetResult();
            }
            var totp = new Totp(Encoding.UTF8.GetBytes(Key), 5, 8);

            var value1 = totp.Compute();
            TestContext.WriteLine($"Value1: {value1} at {DateTime.Now}");

             Task.Delay(6000).GetAwaiter().GetResult();

            var value2 = totp.Compute();
            TestContext.WriteLine($"Value2: {value2} at {DateTime.Now}");

            Assert.AreNotEqual(value1, value2);
        }
    }
}