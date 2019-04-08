using Konscious.Security.Cryptography;
using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace PasswordCracker
{
    class Program
    {
        private static int HASH_SIZE = 256;
        private static int NUMBER_OF_ITERATIONS = 40;
        private static int NUMBER_OF_LINES = 999999;

        public static string GenerateHashSHA256(string password, string salt)
        {
            using (var sha256 = SHA256.Create())
            {
                var pwBytes = Encoding.UTF8.GetBytes(password);
                var saltBytes = Convert.FromBase64String(salt);
                var hash = new byte[pwBytes.Length + saltBytes.Length];

                for (int i = 0; i < pwBytes.Length; i++)
                {
                    hash[i] = pwBytes[i];
                }

                for (int i = 0; i < saltBytes.Length; i++)
                {
                    hash[pwBytes.Length + i] = saltBytes[i];
                }

                var computed = Convert.ToBase64String(sha256.ComputeHash(hash));

                return computed;
            }
        }

        public static string GenerateHashSHA512(string password, string salt)
        {
            using (var sha512 = SHA512.Create())
            {
                var pwBytes = Encoding.UTF8.GetBytes(password);
                var saltBytes = Convert.FromBase64String(salt);
                var hash = new byte[pwBytes.Length + saltBytes.Length];

                for (int i = 0; i < pwBytes.Length; i++)
                {
                    hash[i] = pwBytes[i];
                }

                for (int i = 0; i < saltBytes.Length; i++)
                {
                    hash[pwBytes.Length + i] = saltBytes[i];
                }

                var computed = Convert.ToBase64String(sha512.ComputeHash(hash));

                return computed;
            }
        }

        public static string GenerateHashSHA1(string password, string salt)
        {
            using (var sha1 = SHA1.Create())
            {
                var pwBytes = Encoding.UTF8.GetBytes(password);
                var saltBytes = Convert.FromBase64String(salt);
                var hash = new byte[pwBytes.Length + saltBytes.Length];

                for (int i = 0; i < pwBytes.Length; i++)
                {
                    hash[i] = pwBytes[i];
                }

                for (int i = 0; i < saltBytes.Length; i++)
                {
                    hash[pwBytes.Length + i] = saltBytes[i];
                }

                var computed = Convert.ToBase64String(sha1.ComputeHash(hash));

                return computed;
            }
        }

        public static string GenerateHashPBKDF2(string password, string salt)
        {
            var saltBytes = Convert.FromBase64String(salt);
            var pbkdf2 = new Rfc2898DeriveBytes(password, saltBytes, NUMBER_OF_ITERATIONS, HashAlgorithmName.SHA256);

            var hashBytes = pbkdf2.GetBytes(HASH_SIZE);
            var hash = Convert.ToBase64String(hashBytes);

            return hash;
        }

        public static string GenerateHashArgon2(string password, string salt)
        {
            var pwBytes = Encoding.UTF8.GetBytes(password);
            var saltBytes = Convert.FromBase64String(salt);

            var argon = new Argon2i(pwBytes)
            {
                DegreeOfParallelism = 16,
                MemorySize = 8192,
                Iterations = NUMBER_OF_ITERATIONS,
                Salt = saltBytes
            };

            var hashBytes = argon.GetBytes(HASH_SIZE);
            var hash = Convert.ToBase64String(hashBytes);

            return hash;
        }

        public static string GenerateHash(string password, string salt, string algorithm)
        {
            switch (algorithm)
            {
                case "SHA256":
                    return GenerateHashSHA256(password, salt);

                case "SHA512":
                    return GenerateHashSHA512(password, salt);

                case "PBKDF2-SHA256":
                    return GenerateHashPBKDF2(password, salt);

                case "Argon2":
                    return GenerateHashArgon2(password, salt);

                case "SHA1":
                    return GenerateHashSHA1(password, salt);

                default:
                    return "";
            }
        }

        public static void FindPassword(string hash, string salt, string algorithm)
        {
            var stopwatch = new Stopwatch();
            var streamReader = new StreamReader($@"{Directory.GetCurrentDirectory()}\wordlist.txt");
            string line;
            string foundPassword = null;

            stopwatch.Start();

            int lineNumber = 1;

            while (streamReader.BaseStream != null && (line = streamReader.ReadLine()) != null)
            {
                var generatedHash = GenerateHash(line, salt, algorithm);

                Console.WriteLine($"Line {lineNumber}/{NUMBER_OF_LINES + 1}");
                lineNumber++;

                if (generatedHash == hash)
                {
                    streamReader.Close();
                    foundPassword = line;
                }
            }

            streamReader.Close();
            stopwatch.Stop();

            var elapsedTime = stopwatch.Elapsed;

            var elapsedTimeFormatted = "Completed in ";

            if (elapsedTime.Hours != 0)
            {
                elapsedTimeFormatted += $"{elapsedTime.Hours} Hours";
            }

            if (elapsedTime.Minutes != 0)
            {
                elapsedTimeFormatted += elapsedTime.Hours != 0 ? " and " : "";
                elapsedTimeFormatted += $"{elapsedTime.Minutes} Minutes";
            }

            if (elapsedTime.Seconds != 0)
            {
                elapsedTimeFormatted += elapsedTime.Hours != 0 || elapsedTime.Minutes != 0 ? " and " : "";
                elapsedTimeFormatted += $"{elapsedTime.Seconds} Seconds";
            }

            if (elapsedTime.Milliseconds != 0)
            {
                elapsedTimeFormatted += elapsedTime.Hours != 0 || elapsedTime.Minutes != 0 || elapsedTime.Seconds != 0 ? " and " : "";
                elapsedTimeFormatted += $"{elapsedTime.Milliseconds} Milliseconds";
            }

            elapsedTimeFormatted += ".";

            if (foundPassword != null)
            {
                Console.WriteLine($"The password is: {foundPassword}");
            }
            else
            {
                Console.WriteLine("Sorry, but the password was not found.");
            }

            Console.WriteLine($"Algorithm used: {algorithm}");
            Console.WriteLine(elapsedTimeFormatted);
        }

        public static string GetUniqueKey(int size)
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
            Console.WriteLine("Generating wordlist...\n\n");

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

                w.WriteLine("Test12345Test12345Test12345");
            }
        }

        static void Main(string[] args)
        {
            Console.SetIn(new StreamReader(Console.OpenStandardInput(8192)));

            while (true)
            {
                Console.Write("1.Crack passwords\n2.Quit\nI want to do: ");
                var input = Console.ReadLine();

                if (input == "1")
                {
                    CreateWordlist();
                    Console.Write("Please enter your password hash: ");
                    var hash = Console.ReadLine();

                    Console.Write("Please enter your password salt: ");
                    var salt = Console.ReadLine();

                    Console.Write("1.SHA256\n2.SHA512\n3.PBKDF2-SHA256\n4.Argon2\n5.SHA1\nPlease select a hashing algorithm: ");
                    var selectedHashAlgorithm = Console.ReadLine();

                    switch (selectedHashAlgorithm)
                    {
                        case "1":
                            FindPassword(hash, salt, "SHA256");
                            break;

                        case "2":
                            FindPassword(hash, salt, "SHA512");
                            break;

                        case "3":
                            FindPassword(hash, salt, "PBKDF2-SHA256");
                            break;

                        case "4":
                            FindPassword(hash, salt, "Argon2");
                            break;

                        case "5":
                            FindPassword(hash, salt, "SHA1");
                            break;

                        default:
                            Console.WriteLine("Invalid number selected.");
                            break;
                    }

                    Console.WriteLine("\n\n");
                }
                else if (input == "2")
                {
                    break;
                }
            }
        }
    }
}
