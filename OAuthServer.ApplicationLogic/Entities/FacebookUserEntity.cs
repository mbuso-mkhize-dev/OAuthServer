using OAuthServer.EntityFramework.Core.Models;
using System;
using System.Collections.Generic;
using System.Text;

namespace OAuthServer.ApplicationLogic.Entities
{
    public class FacebookUserEntity
    {
        public User IdentityUser { get; set; }

        public FacebookAccessToken FacebookAccessToken { get; set; }

        public FacebookUser FacebookUser { get; set; }
    }
}
