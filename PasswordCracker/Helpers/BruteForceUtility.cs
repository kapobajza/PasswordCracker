using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PasswordCracker.Helpers
{
    public class BruteForceUtility
    {
        private static string result = null;

        private static bool isMatched = false;

        private static string algorithm = "";

        private static int charactersToTestLength = 0;
        private static long computedKeys = 0;

        private static char[] charactersToTest =
        {
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
            'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
            'u', 'v', 'w', 'x', 'y', 'z','A','B','C','D','E',
            'F','G','H','I','J','K','L','M','N','O','P','Q','R',
            'S','T','U','V','W','X','Y','Z','1','2','3','4','5',
            '6','7','8','9','0','!','$','#','@','-'
        };

        public static string FindPasswordWithBruteForce(string hash, string salt, string algorithmUsed, char[] charsToTest, int estimatedLength)
        {
            isMatched = false;
            result = null;

            charactersToTest = charsToTest ?? charactersToTest;
            charactersToTestLength = charactersToTest.Length;

            var estimatedPasswordLength = estimatedLength;
            var lengthNotSelected = estimatedLength == 0 ? true : false;
            algorithm = algorithmUsed;

            while (!isMatched)
            {
                if (lengthNotSelected)
                {
                    estimatedPasswordLength++;
                }

                StartBruteForce(estimatedPasswordLength, hash, salt);
            }

            return result;
        }

        private static void StartBruteForce(int keyLength, string passwordHash, string salt)
        {
            var keyChars = CreateCharArray(keyLength, charactersToTest[0]);
            var indexOfLastChar = keyLength - 1;
            CreateNewKey(0, keyChars, keyLength, indexOfLastChar, passwordHash, salt);
        }

        private static char[] CreateCharArray(int length, char defaultChar)
        {
            return (from c in new char[length] select defaultChar).ToArray();
        }

        private static void CreateNewKey(int currentCharPosition, char[] keyChars, int keyLength, int indexOfLastChar, string passwordHash, string salt)
        {
            var nextCharPosition = currentCharPosition + 1;

            for (int i = 0; i < charactersToTestLength; i++)
            {
                keyChars[currentCharPosition] = charactersToTest[i];

                if (currentCharPosition < indexOfLastChar)
                {
                    CreateNewKey(nextCharPosition, keyChars, keyLength, indexOfLastChar, passwordHash, salt);
                }
                else
                {
                    computedKeys++;
                    var computedChars = new string(keyChars);
                    var computedHash = HashGenerator.GenerateHash(computedChars, salt, algorithm);

                    if (computedHash == passwordHash)
                    {
                        if (!isMatched)
                        {
                            isMatched = true;
                            result = new string(keyChars);
                        }

                        return;
                    }
                }
            }
        }
    }
}
