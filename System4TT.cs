using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SCREW.Auth.System4TT
{
    public class System4TT
    {
        public string GenerateSecretKey()
        {
            string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:,.<>?";
            StringBuilder codeBuilder = new StringBuilder();
            Random random = new Random();

            for (int i = 0; i < 64; i++)
            {
                int index = random.Next(chars.Length);
                codeBuilder.Append(chars[index]);
            }

            return codeBuilder.ToString();
        }

        public string EncodeSecretKey(string secretKey)
        {
            byte[] bytesToEncode = System.Text.Encoding.UTF8.GetBytes(secretKey);
            string base64String = Convert.ToBase64String(bytesToEncode);
            return base64String;
        }

        public string DecodeSecretKey(string base64Key)
        {
            byte[] bytesToDecode = Convert.FromBase64String(base64Key);
            string decodedString = System.Text.Encoding.UTF8.GetString(bytesToDecode);
            return decodedString;
        }
    }
}
