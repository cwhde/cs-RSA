namespace RSA.commons;

public interface ICommonRSAUnitTest
{
    void GenerateKeys_ShouldNotErrorAndReturnWorkingKeysInAllSizes();
    void EncryptString_ShouldRunWithProvenKeysOfMultipleFormats();
    void DecryptString_ShouldOutputCorrectTextWithProvenKeysOfMultipleFormats();
    void EncryptString_ShouldThrowExceptionWithInvalidPadding();
    void DecryptString_ShouldThrowExceptionWithInvalidPadding();
    void TestCompleteFlowPKCS1();
    void TestCompleteFlowOAEPSha1();
    void TestCompleteFlowOAEPSha256();
}