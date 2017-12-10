using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNetCore.Identity;
using NHibernate.Proxy;

namespace NHibernate.AspNetCore.Identity
{
    public class IdentityUser : IdentityUser<string>, IEquatable<IdentityUser>
    {
        public virtual DateTime? LockoutEndDateUtc { get; set; }

        public virtual ICollection<IdentityRole> Roles { get; protected set; }

        public virtual ICollection<IdentityUserClaim> Claims { get; protected set; }

        public virtual ICollection<IdentityUserLogin> Logins { get; protected set; }

        public virtual ICollection<IdentityUserToken> Tokens { get; protected set; }

        public IdentityUser()
        {
        }

        public IdentityUser(string userName)
            : this()
        {
            this.UserName = userName;
        }

        public virtual void AddToken(IdentityUserToken<string> token)
        {
            if (token == null)
                throw new ArgumentNullException(nameof(token));
            EnsureTokensCollection();
            var modelToken = token as IdentityUserToken ?? new IdentityUserToken(token);
            AddToCollection(this.Tokens, modelToken);
        }

        public virtual bool RemoveToken(IdentityUserToken<string> token)
        {
            if (token == null)
                throw new ArgumentNullException(nameof(token));
            var modelToken = token as IdentityUserToken ?? new IdentityUserToken(token);
            return RemoveFromCollection(this.Tokens, modelToken);
        }

        public virtual void AddRole(IdentityRole role)
        {
            EnsureRolesCollection();
            AddToCollection(this.Roles, role);
        }

        public virtual bool RemoveRole(IdentityRole role)
        {
            return RemoveFromCollection(this.Roles, role);
        }

        public virtual void AddClaim(IdentityUserClaim claim)
        {
            EnsureClaimsCollection();
            AddToCollection(this.Claims, claim);
        }

        public virtual bool RemoveClaim(IdentityUserClaim claim)
        {
            return RemoveFromCollection(this.Claims, claim);
        }

        public virtual void AddLogin(IdentityUserLogin login)
        {
            EnsureLoginsCollection();
            AddToCollection(this.Logins, login);
        }

        public virtual bool RemoveLogin(IdentityUserLogin login)
        {
            return RemoveFromCollection(this.Logins, login);
        }

        public virtual bool Equals(IdentityUser other)
        {
            if (ReferenceEquals(null, other))
                return false;
            if (ReferenceEquals(this, other))
                return true;
            if (!this.GetType().IsUnproxiedTypeEqual(other.GetType()))
                return false;
            if (this.Id == null && other.Id == null)
                return StringComparer.OrdinalIgnoreCase.Equals(this.UserName, other.UserName);

            return StringComparer.OrdinalIgnoreCase.Equals(this.Id, other.Id);
        }

        public override bool Equals(object obj)
        {
            return Equals(obj as IdentityUser);
        }

        public override int GetHashCode()
        {
            return this.Id?.GetHashCode() ?? UserName?.GetHashCode() ?? 0;
        }

        private void EnsureLoginsCollection()
        {
            if (this.Logins == null)
                this.Logins = new List<IdentityUserLogin>();
        }

        private void EnsureTokensCollection()
        {
            if (this.Tokens == null)
                this.Tokens = new List<IdentityUserToken>();
        }

        private void EnsureRolesCollection()
        {
            if (this.Roles == null)
                this.Roles = new List<IdentityRole>();
        }

        private void EnsureClaimsCollection()
        {
            if (this.Claims == null)
                this.Claims = new List<IdentityUserClaim>();
        }

        private void AddToCollection<T>(ICollection<T> collection, T item)
        {
            if (collection == null)
                throw new ArgumentNullException(nameof(collection));
            if (item == null)
                throw new ArgumentNullException(nameof(item));

            if (!collection.Contains(item))
                collection.Add(item);
        }

        private bool RemoveFromCollection<T>(ICollection<T> collection, T item)
            where T : class
        {
            if (item == null)
                throw new ArgumentNullException(nameof(item));

            var toRemove = collection?.SingleOrDefault(i => i.Equals(item));
            return toRemove != null && (collection?.Remove(toRemove)).GetValueOrDefault();
        }
    }
}