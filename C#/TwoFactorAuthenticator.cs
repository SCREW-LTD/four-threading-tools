using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SCREW.Auth.System4TT
{
    public class TwoFactorAuthenticator
    {
        private const int AuthenticationCodeLength = 6;
        private readonly byte[] secretKeyBytes;

        public TwoFactorAuthenticator(string secretKey)
        {
            secretKeyBytes = Encoding.ASCII.GetBytes(secretKey);
        }

        private long GetCurrentUnixTimestamp()
        {
            return DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 100 * 100;
        }

        private byte[] GetHmacSha1(byte[] keyBytes, byte[] data)
        {
            using (HMACSHA1 hmac = new HMACSHA1(keyBytes))
            {
                return hmac.ComputeHash(data);
            }
        }

        private int GetDynamicTruncation(byte[] hmacSha1)
        {
            int offset = hmacSha1[hmacSha1.Length - 1] & 0x0F;
            return ((hmacSha1[offset] & 0x7F) << 24) |
                   ((hmacSha1[offset + 1] & 0xFF) << 16) |
                   ((hmacSha1[offset + 2] & 0xFF) << 8) |
                   (hmacSha1[offset + 3] & 0xFF);
        }

        private string GenerateOTP(long unixTimestamp)
        {
            byte[] timestampBytes = BitConverter.GetBytes(unixTimestamp);

            if (BitConverter.IsLittleEndian)
                Array.Reverse(timestampBytes);

            byte[] hmacSha1 = GetHmacSha1(secretKeyBytes, timestampBytes);
            int otpValue = GetDynamicTruncation(hmacSha1) % 1000000;
            return otpValue.ToString("D6");
        }

        public string GenerateAuthenticationCode()
        {
            long unixTimestamp = GetCurrentUnixTimestamp();
            return GenerateOTP(unixTimestamp);
        }

        public bool VerifyAuthenticationCode(string userProvidedCode)
        {
            long unixTimestamp = GetCurrentUnixTimestamp();
            for (int i = -30; i <= 30; i++)
            {
                string expectedCode = GenerateOTP(unixTimestamp + i);
                if (userProvidedCode == expectedCode)
                    return true;
            }
            return false;
        }
    }
}
