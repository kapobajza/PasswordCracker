using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace PasswordCracker.Helpers
{
    public class WordlistUtility
    {
        private static readonly int NUMBER_OF_LINES = 99999;

        private static string GetUniqueKey(int size)
        {
            char[] chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_-".ToCharArray();
            byte[] data = new byte[size];
            using (RNGCryptoServiceProvider crypto = new RNGCryptoServiceProvider())
            {
                crypto.GetBytes(data);
            }

            StringBuilder result = new StringBuilder(size);

            foreach (byte b in data)
            {
                result.Append(chars[b % (chars.Length)]);
            }

            return result.ToString();
        }

        public static void CreateWordlist()
        {
            Console.WriteLine("Generating wordlist...\n");

            var fileLocation = $@"{Directory.GetCurrentDirectory()}\wordlist.txt";

            if (File.Exists(fileLocation))
            {
                File.Delete(fileLocation);
            }

            using (StreamWriter w = File.AppendText(fileLocation))
            {
                for (int i = 0; i < NUMBER_OF_LINES; i++)
                {
                    var ss = GetUniqueKey(50);
                    w.WriteLine(ss);
                }

                w.WriteLine("test");
            }
        }

        public static string FindPasswordWithWordlist(string hash, string salt, string algorithm)
        {
            var streamReader = new StreamReader($@"{Directory.GetCurrentDirectory()}\wordlist.txt");
            int lineNumber = 1;
            string line;

            while (streamReader.BaseStream != null && (line = streamReader.ReadLine()) != null)
            {
                var generatedHash = HashGenerator.GenerateHash(line, salt, algorithm);

                Console.WriteLine($"Line {lineNumber}/{NUMBER_OF_LINES + 1}");
                lineNumber++;

                if (generatedHash == hash)
                {
                    streamReader.Close();
                    return line;
                }
            }

            streamReader.Close();
            return null;
        }
    }
}
