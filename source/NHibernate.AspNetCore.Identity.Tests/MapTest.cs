using System;
using FluentNHibernate.Testing;
using NHibernate.AspNetCore.Identity.Tests.Models;
using Xunit;

namespace NHibernate.AspNetCore.Identity.Tests
{
    public class MapTest : IDisposable
    {
        private readonly ISession _session;

        public MapTest()
        {
            var factory = SessionFactoryProvider.Instance.SessionFactory;
            this._session = factory.OpenSession();
            SessionFactoryProvider.Instance.BuildSchema();
        }

        [Fact]
        public void CanCorrectlyMapFoo()
        {
            new PersistenceSpecification<Foo>(this._session)
                .CheckProperty(c => c.String, "Foo")
                .CheckReference(r => r.User, new ApplicationUser { UserName = "FooUser" })
                .VerifyTheMappings();
        }

        [Fact]
        public void CanCorrectlyMapIdentityUser()
        {
            new PersistenceSpecification<IdentityUser>(this._session)
                .CheckProperty(c => c.UserName, "Lukz")
                .VerifyTheMappings();
        }

        [Fact]
        public void CanCorrectlyMapApplicationUser()
        {
            new PersistenceSpecification<ApplicationUser>(this._session)
                .CheckProperty(c => c.UserName, "Lukz")
                .VerifyTheMappings();
        }

        [Fact]
        public void CanCorrectlyMapCascadeLogins()
        {
            new PersistenceSpecification<IdentityUser>(this._session)
                .CheckProperty(c => c.UserName, "Letícia")
                .CheckComponentList(c => c.Logins, new[] { new IdentityUserLogin { LoginProvider = "Provider", ProviderKey = "Key" } })
                //.CheckList(l => l.Logins, new[] { new IdentityUserLogin { LoginProvider = "Provider", ProviderKey = "Key" } })
                //.CheckList(l => l.Logins, new[] { new IdentityUserLogin { LoginProvider = "Provider", ProviderKey = "Key" } }, (user, login) => user.Logins.Add(login))
                .VerifyTheMappings();
        }

        public void Dispose()
        {
            this._session?.Dispose();
        }
    }
}
