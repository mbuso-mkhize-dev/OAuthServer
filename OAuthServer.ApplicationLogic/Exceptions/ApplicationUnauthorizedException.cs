using System;

namespace OAuthServer.ApplicationLogic.Exceptions
{
    public class ApplicationUnauthorizedException : Exception
    {
        public ApplicationUnauthorizedException()
        {
        }

        public ApplicationUnauthorizedException(string message) : base(message)
        {
        }

        public ApplicationUnauthorizedException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}