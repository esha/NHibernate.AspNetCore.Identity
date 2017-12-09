using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace NHibernate.AspNetCore.Identity.Tests.Models
{
    public class Entity
    {
        public virtual Guid Id { get; set; }
    }

    public class Foo : Entity
    {
        public virtual string String { get; set; }
        public virtual ApplicationUser User { get; set; }
    }
}