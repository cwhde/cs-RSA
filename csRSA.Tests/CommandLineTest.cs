using System;
using JetBrains.Annotations;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RSA.CLI;

namespace csRSA.Tests;

[TestClass]
[TestSubject(typeof(CommandLine))]
public class CommandLineTest
{

    [TestMethod]
    // Runs the tests implemented in the CommandLine class and passes if there is no exception
    public void RunImplementedTests()
    {
        CommandLine testCommandLine = new CommandLine(); 
        testCommandLine.Run(isTesting: true); 
        Assert.IsTrue(testCommandLine.TestSuccess);
    }
}