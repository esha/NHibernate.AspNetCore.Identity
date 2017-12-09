using System.Collections.Generic;
using Microsoft.AspNetCore.Identity;

namespace NHibernate.AspNetCore.Identity
{
    public class IdentityRole : IdentityRole<string>
    {
        public virtual ICollection<IdentityUser> Users { get; protected set; }

        public IdentityRole()
        {
        }

        public IdentityRole(string roleName) : this()
        {
            this.Name = roleName;
        }
    }
}