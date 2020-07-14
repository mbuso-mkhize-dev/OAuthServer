using System;

namespace OAuthServer.EntityFramework.Core.Interfaces
{
    public interface ITimestamp
    {
        DateTimeOffset CreatedAt { get; set; }

        DateTimeOffset UpdatedAt { get; set; }
    }
}