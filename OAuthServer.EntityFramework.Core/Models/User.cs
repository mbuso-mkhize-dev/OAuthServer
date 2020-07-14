using Microsoft.AspNetCore.Identity;
using OAuthServer.EntityFramework.Core.Interfaces;
using System;

namespace OAuthServer.EntityFramework.Core.Models
{
    public class User : IdentityUser, ITimestamp
    {
        public string FirstName { get; set; }

        public string LastName { get; set; }

        public DateTimeOffset CreatedAt { get; set; }

        public DateTimeOffset UpdatedAt { get; set; }
    }
}