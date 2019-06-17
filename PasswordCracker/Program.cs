using Konscious.Security.Cryptography;
using PasswordCracker.Helpers;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace PasswordCracker
{
    class Program
    {
        public static void FindPassword(string hash, string salt, string input, string crackingMethod)
        {
            var stopwatch = new Stopwatch();
            string foundPassword = null;
            string algorithm = "";

            switch (input)
            {
                case "1":
                    algorithm = "SHA256";
                    break;

                case "2":
                    algorithm = "SHA512";
                    break;

                case "3":
                    algorithm = "PBKDF2-SHA256";
                    break;

                case "4":
                    algorithm = "Argon2";
                    break;

                case "5":
                    algorithm = "SHA1";
                    break;

                default:
                    Console.WriteLine("Neispravan unos.");
                    return;
            }

            if (crackingMethod == "1")
            {
                WordlistUtility.CreateWordlist();

                stopwatch.Start();
                foundPassword = WordlistUtility.FindPasswordWithWordlist(hash, salt, algorithm);
            }
            else if (crackingMethod == "2")
            {
                Console.Write("\nMolimo da unesete karaktere za brute force metodu (ostavite prazno za defaultn-e vrijednosti): ");
                var selectedChars = Console.ReadLine();
                char[] charArray = null;

                if (!string.IsNullOrWhiteSpace(selectedChars))
                {
                    charArray = selectedChars.Distinct().ToArray();
                }

                int estimatedLength = 0;
                bool parsed = false;

                do
                {
                    Console.Write("\nMolimo da unesete dužinu lozinke (ostavite prazno ukoliko ne znate): ");
                    var estimatedSelectedLength = Console.ReadLine();

                    if (estimatedSelectedLength == "")
                    {
                        break;
                    }

                    parsed = int.TryParse(estimatedSelectedLength, out estimatedLength);
                } while (!parsed);

                stopwatch.Start();
                Console.WriteLine("U toku...");

                foundPassword = BruteForceUtility.FindPasswordWithBruteForce(hash, salt, algorithm, charArray, estimatedLength);
            }
            else
            {
                stopwatch.Stop();
                return;
            }

            stopwatch.Stop();

            var elapsedTimeFormatted = ElapsedTimeFormatter.FormatElapsedTime(stopwatch.Elapsed, "Završeno za");

            if (!string.IsNullOrEmpty(foundPassword))
            {
                Console.WriteLine($"\nPronađena lozinka je: {foundPassword}");
            }
            else
            {
                Console.WriteLine("\nŽao nam je, lozinka nije pronađena.");
            }

            Console.WriteLine($"Korišteni algoritam: {algorithm}");
            Console.WriteLine(elapsedTimeFormatted);
        }

        static void Main(string[] args)
        {
            Console.SetIn(new StreamReader(Console.OpenStandardInput(8192)));

            while (true)
            {
                Console.Write("1.Crack lozinke\n2.Izlaz\nOdaberite: ");
                var input = Console.ReadLine();

                if (input == "1")
                {
                    Console.Write("Molimo unesite hash lozinke: ");
                    var hash = Console.ReadLine();

                    Console.Write("Molimo unesite salt lozinke: ");
                    var salt = Console.ReadLine();

                    Console.Write("\n1.SHA256\n2.SHA512\n3.PBKDF2-SHA256\n4.Argon2\n5.SHA1\nMolimo odaberite hash algoritam: ");
                    var selectedHashAlgorithm = Console.ReadLine();

                    Console.Write("\n1.Word list metoda\n2.Brute force metoda\nMolimo odaberite metodu: ");
                    var selectedCrackingMethod = Console.ReadLine();

                    FindPassword(hash, salt, selectedHashAlgorithm, selectedCrackingMethod);

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
