using System;
using System.Collections.Generic;
using System.Text;

namespace PasswordCracker.Helpers
{
    public class ElapsedTimeFormatter
    {
        public static string FormatElapsedTime(TimeSpan elapsedTime, string message)
        {
            var elapsedTimeFormatted = $"{message} ";

            if (elapsedTime.Hours != 0)
            {
                elapsedTimeFormatted += $"{elapsedTime.Hours} sati";
            }

            if (elapsedTime.Minutes != 0)
            {
                elapsedTimeFormatted += elapsedTime.Hours != 0 ? ", " : "";
                elapsedTimeFormatted += $"{elapsedTime.Minutes} minuta";
            }

            if (elapsedTime.Seconds != 0)
            {
                elapsedTimeFormatted += elapsedTime.Hours != 0 || elapsedTime.Minutes != 0 ? ", " : "";
                elapsedTimeFormatted += $"{elapsedTime.Seconds} sekundi";
            }

            if (elapsedTime.Milliseconds != 0)
            {
                elapsedTimeFormatted += elapsedTime.Hours != 0 || elapsedTime.Minutes != 0 || elapsedTime.Seconds != 0 ? " i " : "";
                elapsedTimeFormatted += $"{elapsedTime.Milliseconds} milisekundi";
            }

            elapsedTimeFormatted += ".";

            return elapsedTimeFormatted;
        }
    }
}
