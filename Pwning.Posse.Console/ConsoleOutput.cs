using System;

namespace Pwning.Posse.CommandLine
{
    public class ConsoleOutput
    {
        public static void ErrorMessage(string message)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(message);
            Console.ResetColor();
        }

        public static void ExceptionMessage(Exception exception)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            var exceptionMessage    = exception.InnerException != null ? exception.InnerException.Message : exception.Message;
            Console.WriteLine(exceptionMessage);
            Console.ResetColor();
        }

        public static void SystemMessage(string message)
        {
            Console.ForegroundColor = ConsoleColor.Green;           
            Console.WriteLine(message);
            Console.ResetColor();            
        }

        public static void HeaderMessage(string message)
        {
            Console.ForegroundColor = ConsoleColor.DarkGreen;
            Console.WriteLine();
            Console.WriteLine(message);
            Console.ResetColor();
        }

        public static void Message(string message)
        {

        }
    }
}
