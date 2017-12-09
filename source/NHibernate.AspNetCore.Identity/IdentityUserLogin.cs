using System;
using Microsoft.AspNetCore.Identity;

namespace NHibernate.AspNetCore.Identity
{
    public class IdentityUserLogin : IdentityUserLogin<string>, IEquatable<IdentityUserLogin>
    {
        public virtual bool Equals(IdentityUserLogin other)
        {
            if (ReferenceEquals(null, other))
                return false;
            if (ReferenceEquals(this, other))
                return true;
            if (other.GetType() != this.GetType())
                return false;

            return this.LoginProvider == other.LoginProvider &&
                   this.ProviderKey == other.ProviderKey &&
                   this.UserId == other.UserId &&
                   this.ProviderDisplayName == other.ProviderDisplayName;
        }

        public override bool Equals(object obj)
        {
            return Equals(obj as IdentityUserLogin);
        }

        public override int GetHashCode()
        {
            return (this.LoginProvider?.GetHashCode() ?? 0) * 31 ^
                   (this.ProviderKey?.GetHashCode() ?? 0) * 31 ^
                   (this.UserId?.GetHashCode() ?? 0) * 31 ^
                   (this.ProviderDisplayName?.GetHashCode() ?? 0) * 31;
        }
    }
}
