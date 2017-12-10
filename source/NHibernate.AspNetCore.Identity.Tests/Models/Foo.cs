using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using FluentNHibernate.Mapping;
using NHibernate.Mapping.ByCode;
using NHibernate.Mapping.ByCode.Conformist;

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

    public class FooMap : ClassMapping<Foo>
    {
        public FooMap()
        {
            this.Table("Foo");
            this.Id(x => x.Id, m => m.Generator(new GuidCombGeneratorDef()));
            this.Property(x => x.String);
            this.ManyToOne(x => x.User);
        }
    }
}