using PandaAuth.ReadinessHarness;
using Xunit;
namespace PandaAuth.Tests;
public sealed class ControlledActorsTests
{
    [Fact]
    public void ProbeIdentitiesAreDerivedFromFullAttemptAndCannotChooseAnExistingSubject()
    {
        var spec=new ControlledTransportSpec(1,new string('a',32),new string('b',64),"https://auth.appliket.com/",5200,5201,5202);
        var names=ControlledActors.Names(spec);
        Assert.Equal(4,names.Length);Assert.All(names,name=>Assert.Contains(spec.Attempt,name));
        Assert.NotEqual(names,ControlledActors.Names(spec with{Attempt=new string('c',32)}));
        Assert.ThrowsAny<Exception>(()=>ControlledActors.Names(spec with{Attempt="original-admin"}));
        Assert.True(Guid.TryParse(ControlledActors.Subject(spec,0),out _));
        Assert.Equal(ControlledActors.Subject(spec,0),ControlledActors.Subject(spec,0));
        Assert.NotEqual(ControlledActors.Subject(spec,0),ControlledActors.Subject(spec,1));
        Assert.ThrowsAny<Exception>(()=>ControlledActors.Subject(spec,3));
    }
    [Fact]
    public async Task ActorCreationCannotRunOutsideTheAdmittedNamespace()
    {
        Assert.Equal(2,await ControlledActors.Dispatch("{}"));
    }
}
