using System;
using System.ComponentModel.DataAnnotations;

namespace OAuthServer.EntityFramework.Core.Models
{
    public class Product
    {
        [Key]
        public Guid Id { get; set; }

        public string Name { get; set; }

        public string Description { get; set; }
    }
}