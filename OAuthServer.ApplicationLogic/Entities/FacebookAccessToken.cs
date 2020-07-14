using System;
using System.Collections.Generic;
using System.Text;

namespace OAuthServer.ApplicationLogic.Entities
{
    public class FacebookAccessToken
    {
        public long ExpiresIn { get; set; }

        public string TokenType { get; set; }

        public string AccessToken { get; set; }
    }
}
