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
    }
    [Fact]
    public async Task ActorCreationCannotRunOutsideTheAdmittedNamespace()
    {
        Assert.Equal(2,await ControlledActors.Dispatch("{}"));
    }
}
