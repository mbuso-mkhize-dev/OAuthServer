using System;
using System.Collections.Generic;
using System.Text;

namespace OAuthServer.ApplicationLogic.Entities
{
    public class UserEntity
    {
        public string UserId { get; set; }

        public string Name { get; set; }

        public string Password { get; set; }

        public string Email { get; set; }
    }
}
