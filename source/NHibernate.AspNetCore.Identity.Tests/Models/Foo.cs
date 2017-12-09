using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using SharpArch.Domain.DomainModel;

namespace NHibernate.AspNetCore.Identity.Tests.Models
{
    public class Foo : Entity
    {
        public virtual string String { get; set; }
        public virtual ApplicationUser User { get; set; }
    }
}