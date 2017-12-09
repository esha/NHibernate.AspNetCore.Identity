using System;
using Microsoft.AspNetCore.Identity;

namespace NHibernate.AspNetCore.Identity
{
    public class IdentityUserToken : IdentityUserToken<string>, IEquatable<IdentityUserToken<string>>, IEquatable<IdentityUserToken>
    {
        public IdentityUserToken()
        {   
        }

        public IdentityUserToken(IdentityUserToken<string> token)
        {
            if (token == null)
                throw new ArgumentNullException(nameof(token));
            this.Name = token.Name;
            this.UserId = token.UserId;
            this.LoginProvider = token.LoginProvider;
            this.Value = token.Value;
        }

        public virtual bool Equals(IdentityUserToken other)
        {
            if (ReferenceEquals(null, other))
                return false;
            if (ReferenceEquals(this, other))
                return true;
            if (other.GetType() != this.GetType())
                return false;
            return this.Name == other.Name &&
                   this.LoginProvider == other.LoginProvider &&
                   this.UserId == other.UserId &&
                   this.Value == other.Value;
        }

        public override bool Equals(object obj)
        {
            return Equals(obj as IdentityUserToken);
        }

        public override int GetHashCode()
        {
            return ((this.Name?.GetHashCode() ?? 0) * 31) ^
                   ((this.LoginProvider?.GetHashCode() ?? 0) * 31) ^
                   ((this.UserId?.GetHashCode() ?? 0) * 31) ^
                   ((this.Value?.GetHashCode() ?? 0) * 31);
        }

        public virtual bool Equals(IdentityUserToken<string> other)
        {
            if (other is null)
            {
                return false;
            }

            if (ReferenceEquals(this, other))
            {
                return true;
            }

            return other.Name == this.Name && other.LoginProvider == this.LoginProvider && other.UserId == this.UserId;
        }
    }
}