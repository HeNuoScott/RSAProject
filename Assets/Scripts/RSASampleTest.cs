using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using System.Collections.Generic;
using System.Collections;
using System.IO;

public class RSASampleTest
{
    string publicKeyJava = @"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCkixtIe0MzCFDW3eCDSq/6SFFN+eK+zg1q62SX
                            TbJprt7zOD6D9A8zU1fTEzY9+0gVUYmOMPOF8jI8EMZOnl2jDUtn3KdD2Uuee3/cmEfMpAN++KMG
                            6Tfm3p3Iz4kw/dLmM1EAkADIp4zFmkvxd/BN+dmT/1Tp87mMUQBS8mvdRwIDAQAB";

    string privateKeyJava = @"MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAKSLG0h7QzMIUNbd4INKr/pIUU35
                             4r7ODWrrZJdNsmmu3vM4PoP0DzNTV9MTNj37SBVRiY4w84XyMjwQxk6eXaMNS2fcp0PZS557f9yY
                             R8ykA374owbpN+bencjPiTD90uYzUQCQAMinjMWaS/F38E352ZP/VOnzuYxRAFLya91HAgMBAAEC
                             gYBXJCSq2jzYhgrqAE+quJ9CGZKVjUV8b3vDqC55wvg96BLDFIJnN5XlRLo6Wu5bHP0r7SbAW0Rd
                             J8ta7DdZ450Kow+k2Z69gYO818cptQXYrs4ky6M48NXeSSoYeGESxW7LGJs++o2nGmVRkhj4DMYY
                             8lur1oYsyDAy/d3B0ucnwQJBAP0Kc2KCOl8xnbXUuoFhJHaVoKPWqdhody5sNHK+11Bgc3/ZhqNM
                             T1uIiiZnB3CTyfKeJAgX0fwde7fmtZHaUO8CQQCmd7a3qXvUbnQao03ITrthGRvGAJSAfTAG/VEx
                             2g1knxUmiq+bek+FGi7UYXYRZ/rVqX934ztTAOnBqVtnK4kpAkEAs6KAqVUkFUJG4LfFM2YAGcM9
                             SDJzXvNCcI1WaoM6nY/rTr7hCvp4d9WlpX+M04nHWtqTX79xTdasZrB9A68FtwJAHXWmIk6eGXQK
                             nAQ2abJ1OrPE1H+ZyDtfWn1N9zKNmDcG+TEl7q/wjq+ZhgBRcrciDtnWMxNFlmTc+WbNRC7SMQJB
                             AIBSE1kfhy3V63db91Gnr789G2QKy3TI46QEY3dirLiXWF3/tt+9K8itjeB22S5S7cWbzJ+2FIFW
                             mFB/DP3ER8Q=";

    string publicKeyPEM = @"-----BEGIN PUBLIC KEY-----
                            MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDe8W+2jrrWY55W8nZcWCBXQSJJ
                            uJxkannRsZbwiwJBftXCzN0wSaujwmT0S0Aqttnqg/sO+jDHVnpph8omZdSvnySt
                            /PiGEqmsk+6AsgZ7eczeokVkrFvVbjq13s6NVF8tgMds/w5VG8+uEECmiHCKM8/V
                            3oXhq7aLPLINFYggcQIDAQAB
                            -----END PUBLIC KEY-----
                            ";

    string privateKeyPEM = @"-----BEGIN RSA PRIVATE KEY-----
                            MIICWwIBAAKBgQDe8W+2jrrWY55W8nZcWCBXQSJJuJxkannRsZbwiwJBftXCzN0w
                            SaujwmT0S0Aqttnqg/sO+jDHVnpph8omZdSvnySt/PiGEqmsk+6AsgZ7eczeokVk
                            rFvVbjq13s6NVF8tgMds/w5VG8+uEECmiHCKM8/V3oXhq7aLPLINFYggcQIDAQAB
                            AoGAN9OnkMRe/u6FKOqgPvGGb7MMvf8vkmmjRaI91NBKaVI0fwpD3SKli2VTWGU7
                            lTaijPottQtriY8bKi/prAHV5wiSetsiPB9DQq8bN3rLtJPG6NCmwiOUhamBg9kD
                            VbqOb/1dg0vGL1zEKxtscaK5yDCBnyX+4LfAR5Upg0Q4t70CQQD8n5XxSdQpHNAf
                            sl26cTxf6YHCzHoqUfDo4SE74jWy8ooNF3qk0jaYy6+N1EOLwpMfm2MeWdxCYFmC
                            9NdbowIDAkEA4exKy9FGTPVkkVhAwva0fm7/mJSHsl7btPTJvmgEfO9eHbozYacQ
                            2PmbZd46uPzaI0LaDh8ICbaLvf8IPiVjewJAXIMUpggjaerjTLhFGsHdGkKpAm1f
                            T6AyWRYY1ZVBlQa9B45Rm4pf9BSjdY0GL2hR+IEvCy5dOvGN1idTtns7gQJAfiqO
                            TqptPxcfdYe6iuZpP95PAO+ZpEQTIEg/zgSa1QZ8Ic/VV+iLoRAr90SWuK4ESALS
                            cWZk/7+g5JbjDImmtwJAfBpGw+TVeMw+2Oo9GJnIM9Ga/hiYQDCkZ9A/4fYrNxxr
                            znkMqFQ28dhYQbKK9/WcPTjHGakpY/2hY/9dki6CJw==
                            -----END RSA PRIVATE KEY-----
                            ";

    private string data = "hello word!";
    //"RIPEMD160",
    //{MD5??RIPEMD160??SHA1??SHA256??SHA384??SHA512}
    private List<string> hashAlgorithmList = new List<string>() { "MD5", "SHA1", "SHA256", "SHA384", "SHA512" };
    
    #region * RSA??????????????????????????????????RSA????????-??????????????????????????????????

    /// <summary>
    /// JAVA????/????
    /// </summary>
    public void RSASign_JAVA_WithVerify()
    {
        foreach (var hashAlgorithm in hashAlgorithmList)
        {
            string signResult = RSAHelper.RSASignJava(data, privateKeyJava, hashAlgorithm);
            bool result = RSAHelper.VerifyJava(data, publicKeyJava, signResult, hashAlgorithm);
            UnityEngine.Debug.Log(signResult);
            UnityEngine.Debug.Log(result);
        }
    }

    /// <summary>
    /// PEM????/????
    /// </summary>
    public void RSASign_PEM_WithVerify()
    {
        foreach (var hashAlgorithm in hashAlgorithmList)
        {
            string signResult = RSAHelper.RSASignPEM(data, privateKeyPEM, hashAlgorithm);
            bool result = RSAHelper.VerifyPEM(data, publicKeyPEM, signResult, hashAlgorithm);
            UnityEngine.Debug.Log(signResult);
            UnityEngine.Debug.Log(result);
        }
    }

    /// <summary>
    /// java??????????
    /// </summary>
    public void RSA_Java_EncryptWithDecrypt()
    {
        string encryptResult = RSAHelper.EncryptJava(publicKeyJava, data);
        string decryptResult = RSAHelper.DecryptJava(privateKeyJava, encryptResult);
        UnityEngine.Debug.Log(encryptResult);
        UnityEngine.Debug.Log(decryptResult);
    }

    /// <summary>
    /// PEM??????????????
    /// </summary>
    public void RSA_PEM_EncryptWithDecrypt()
    {
        string encryptResult = RSAHelper.EncryptPEM(publicKeyPEM, data);
        string decryptResult = RSAHelper.DecryptPEM(privateKeyPEM, encryptResult);
        UnityEngine.Debug.Log(encryptResult);
        UnityEngine.Debug.Log(decryptResult);
    }

    #endregion BouncyCastle????????????????????????????????????

    /// <summary>
    /// BouncyCastle????????????????????????????????????
    /// </summary>
    public void BouncyCastleEncryptWithDecrypt()
    {
        string encryptResult = RSAHelper.EncryptPrivateKeyJava(privateKeyJava, data);
        string decryptResult = RSAHelper.DecryptPublicKeyJava(publicKeyJava, encryptResult);
        UnityEngine.Debug.Log(encryptResult);
        UnityEngine.Debug.Log(decryptResult);
    }

    /// <summary>
    /// BouncyCastle????/????
    /// </summary>
    public void BouncyCastleSignVerify()
    {
        var algorithms = GetAlgorithms();
        foreach (var item in algorithms.Keys)
        {
            if (!item.ToString().Contains("RSA")) continue;
            if (item.ToString() == "SHA-512WITHRSA/PSS")
            {
                UnityEngine.Debug.Log("????SHA-512WITHRSA/PSS ???????????????????????????????????? key is too small");
            }
            string signResult = RSAHelper.RSASignJavaBouncyCastle(data, privateKeyJava, item.ToString());
            bool result = RSAHelper.VerifyJavaBouncyCastle(data, publicKeyJava, signResult, item.ToString());
            UnityEngine.Debug.Log(signResult);
            UnityEngine.Debug.Log(result);
        }
    }

    /// <summary>
    /// ????????????
    /// </summary>
    /// <param name="path"></param>
    /// <param name="fileName"></param>
    /// <returns></returns>
    public string GetTxtFileData(string path, string fileName)
    {
        string keyfile = Path.Combine(path, fileName);
        string data = "";
        if (File.Exists(keyfile))
        {
            StreamReader streamReader = new StreamReader(keyfile);
            data = streamReader.ReadToEnd();
            streamReader.Close();
        }
        return data;
    }

    private IDictionary GetAlgorithms()
    {
        IDictionary algorithms = new Hashtable();
        algorithms["MD2WITHRSA"] = "MD2withRSA";
        algorithms["MD2WITHRSAENCRYPTION"] = "MD2withRSA";
        algorithms[PkcsObjectIdentifiers.MD2WithRsaEncryption.Id] = "MD2withRSA";

        algorithms["MD4WITHRSA"] = "MD4withRSA";
        algorithms["MD4WITHRSAENCRYPTION"] = "MD4withRSA";
        algorithms[PkcsObjectIdentifiers.MD4WithRsaEncryption.Id] = "MD4withRSA";

        algorithms["MD5WITHRSA"] = "MD5withRSA";
        algorithms["MD5WITHRSAENCRYPTION"] = "MD5withRSA";
        algorithms[PkcsObjectIdentifiers.MD5WithRsaEncryption.Id] = "MD5withRSA";

        algorithms["SHA1WITHRSA"] = "SHA-1withRSA";
        algorithms["SHA1WITHRSAENCRYPTION"] = "SHA-1withRSA";
        algorithms[PkcsObjectIdentifiers.Sha1WithRsaEncryption.Id] = "SHA-1withRSA";
        algorithms["SHA-1WITHRSA"] = "SHA-1withRSA";

        algorithms["SHA224WITHRSA"] = "SHA-224withRSA";
        algorithms["SHA224WITHRSAENCRYPTION"] = "SHA-224withRSA";
        algorithms[PkcsObjectIdentifiers.Sha224WithRsaEncryption.Id] = "SHA-224withRSA";
        algorithms["SHA-224WITHRSA"] = "SHA-224withRSA";

        algorithms["SHA256WITHRSA"] = "SHA-256withRSA";
        algorithms["SHA256WITHRSAENCRYPTION"] = "SHA-256withRSA";
        algorithms[PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id] = "SHA-256withRSA";
        algorithms["SHA-256WITHRSA"] = "SHA-256withRSA";

        algorithms["SHA384WITHRSA"] = "SHA-384withRSA";
        algorithms["SHA384WITHRSAENCRYPTION"] = "SHA-384withRSA";
        algorithms[PkcsObjectIdentifiers.Sha384WithRsaEncryption.Id] = "SHA-384withRSA";
        algorithms["SHA-384WITHRSA"] = "SHA-384withRSA";

        algorithms["SHA512WITHRSA"] = "SHA-512withRSA";
        algorithms["SHA512WITHRSAENCRYPTION"] = "SHA-512withRSA";
        algorithms[PkcsObjectIdentifiers.Sha512WithRsaEncryption.Id] = "SHA-512withRSA";
        algorithms["SHA-512WITHRSA"] = "SHA-512withRSA";

        algorithms["PSSWITHRSA"] = "PSSwithRSA";
        algorithms["RSASSA-PSS"] = "PSSwithRSA";
        algorithms[PkcsObjectIdentifiers.IdRsassaPss.Id] = "PSSwithRSA";
        algorithms["RSAPSS"] = "PSSwithRSA";

        algorithms["SHA1WITHRSAANDMGF1"] = "SHA-1withRSAandMGF1";
        algorithms["SHA-1WITHRSAANDMGF1"] = "SHA-1withRSAandMGF1";
        algorithms["SHA1WITHRSA/PSS"] = "SHA-1withRSAandMGF1";
        algorithms["SHA-1WITHRSA/PSS"] = "SHA-1withRSAandMGF1";

        algorithms["SHA224WITHRSAANDMGF1"] = "SHA-224withRSAandMGF1";
        algorithms["SHA-224WITHRSAANDMGF1"] = "SHA-224withRSAandMGF1";
        algorithms["SHA224WITHRSA/PSS"] = "SHA-224withRSAandMGF1";
        algorithms["SHA-224WITHRSA/PSS"] = "SHA-224withRSAandMGF1";

        algorithms["SHA256WITHRSAANDMGF1"] = "SHA-256withRSAandMGF1";
        algorithms["SHA-256WITHRSAANDMGF1"] = "SHA-256withRSAandMGF1";
        algorithms["SHA256WITHRSA/PSS"] = "SHA-256withRSAandMGF1";
        algorithms["SHA-256WITHRSA/PSS"] = "SHA-256withRSAandMGF1";

        algorithms["SHA384WITHRSAANDMGF1"] = "SHA-384withRSAandMGF1";
        algorithms["SHA-384WITHRSAANDMGF1"] = "SHA-384withRSAandMGF1";
        algorithms["SHA384WITHRSA/PSS"] = "SHA-384withRSAandMGF1";
        algorithms["SHA-384WITHRSA/PSS"] = "SHA-384withRSAandMGF1";

        algorithms["SHA512WITHRSAANDMGF1"] = "SHA-512withRSAandMGF1";
        algorithms["SHA-512WITHRSAANDMGF1"] = "SHA-512withRSAandMGF1";
        algorithms["SHA512WITHRSA/PSS"] = "SHA-512withRSAandMGF1";
        algorithms["SHA-512WITHRSA/PSS"] = "SHA-512withRSAandMGF1";

        algorithms["RIPEMD128WITHRSA"] = "RIPEMD128withRSA";
        algorithms["RIPEMD128WITHRSAENCRYPTION"] = "RIPEMD128withRSA";
        algorithms[TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD128.Id] = "RIPEMD128withRSA";

        algorithms["RIPEMD160WITHRSA"] = "RIPEMD160withRSA";
        algorithms["RIPEMD160WITHRSAENCRYPTION"] = "RIPEMD160withRSA";
        algorithms[TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD160.Id] = "RIPEMD160withRSA";

        algorithms["RIPEMD256WITHRSA"] = "RIPEMD256withRSA";
        algorithms["RIPEMD256WITHRSAENCRYPTION"] = "RIPEMD256withRSA";
        algorithms[TeleTrusTObjectIdentifiers.RsaSignatureWithRipeMD256.Id] = "RIPEMD256withRSA";

        algorithms["NONEWITHRSA"] = "RSA";
        algorithms["RSAWITHNONE"] = "RSA";
        algorithms["RAWRSA"] = "RSA";

        algorithms["RAWRSAPSS"] = "RAWRSASSA-PSS";
        algorithms["NONEWITHRSAPSS"] = "RAWRSASSA-PSS";
        algorithms["NONEWITHRSASSA-PSS"] = "RAWRSASSA-PSS";

        algorithms["NONEWITHDSA"] = "NONEwithDSA";
        algorithms["DSAWITHNONE"] = "NONEwithDSA";
        algorithms["RAWDSA"] = "NONEwithDSA";

        algorithms["DSA"] = "SHA-1withDSA";
        algorithms["DSAWITHSHA1"] = "SHA-1withDSA";
        algorithms["DSAWITHSHA-1"] = "SHA-1withDSA";
        algorithms["SHA/DSA"] = "SHA-1withDSA";
        algorithms["SHA1/DSA"] = "SHA-1withDSA";
        algorithms["SHA-1/DSA"] = "SHA-1withDSA";
        algorithms["SHA1WITHDSA"] = "SHA-1withDSA";
        algorithms["SHA-1WITHDSA"] = "SHA-1withDSA";
        algorithms[X9ObjectIdentifiers.IdDsaWithSha1.Id] = "SHA-1withDSA";

        algorithms["DSAWITHSHA224"] = "SHA-224withDSA";
        algorithms["DSAWITHSHA-224"] = "SHA-224withDSA";
        algorithms["SHA224/DSA"] = "SHA-224withDSA";
        algorithms["SHA-224/DSA"] = "SHA-224withDSA";
        algorithms["SHA224WITHDSA"] = "SHA-224withDSA";
        algorithms["SHA-224WITHDSA"] = "SHA-224withDSA";
        algorithms[NistObjectIdentifiers.DsaWithSha224.Id] = "SHA-224withDSA";

        algorithms["DSAWITHSHA256"] = "SHA-256withDSA";
        algorithms["DSAWITHSHA-256"] = "SHA-256withDSA";
        algorithms["SHA256/DSA"] = "SHA-256withDSA";
        algorithms["SHA-256/DSA"] = "SHA-256withDSA";
        algorithms["SHA256WITHDSA"] = "SHA-256withDSA";
        algorithms["SHA-256WITHDSA"] = "SHA-256withDSA";
        algorithms[NistObjectIdentifiers.DsaWithSha256.Id] = "SHA-256withDSA";

        algorithms["DSAWITHSHA384"] = "SHA-384withDSA";
        algorithms["DSAWITHSHA-384"] = "SHA-384withDSA";
        algorithms["SHA384/DSA"] = "SHA-384withDSA";
        algorithms["SHA-384/DSA"] = "SHA-384withDSA";
        algorithms["SHA384WITHDSA"] = "SHA-384withDSA";
        algorithms["SHA-384WITHDSA"] = "SHA-384withDSA";
        algorithms[NistObjectIdentifiers.DsaWithSha384.Id] = "SHA-384withDSA";

        algorithms["DSAWITHSHA512"] = "SHA-512withDSA";
        algorithms["DSAWITHSHA-512"] = "SHA-512withDSA";
        algorithms["SHA512/DSA"] = "SHA-512withDSA";
        algorithms["SHA-512/DSA"] = "SHA-512withDSA";
        algorithms["SHA512WITHDSA"] = "SHA-512withDSA";
        algorithms["SHA-512WITHDSA"] = "SHA-512withDSA";
        algorithms[NistObjectIdentifiers.DsaWithSha512.Id] = "SHA-512withDSA";

        algorithms["NONEWITHECDSA"] = "NONEwithECDSA";
        algorithms["ECDSAWITHNONE"] = "NONEwithECDSA";

        algorithms["ECDSA"] = "SHA-1withECDSA";
        algorithms["SHA1/ECDSA"] = "SHA-1withECDSA";
        algorithms["SHA-1/ECDSA"] = "SHA-1withECDSA";
        algorithms["ECDSAWITHSHA1"] = "SHA-1withECDSA";
        algorithms["ECDSAWITHSHA-1"] = "SHA-1withECDSA";
        algorithms["SHA1WITHECDSA"] = "SHA-1withECDSA";
        algorithms["SHA-1WITHECDSA"] = "SHA-1withECDSA";
        algorithms[X9ObjectIdentifiers.ECDsaWithSha1.Id] = "SHA-1withECDSA";
        algorithms[TeleTrusTObjectIdentifiers.ECSignWithSha1.Id] = "SHA-1withECDSA";

        algorithms["SHA224/ECDSA"] = "SHA-224withECDSA";
        algorithms["SHA-224/ECDSA"] = "SHA-224withECDSA";
        algorithms["ECDSAWITHSHA224"] = "SHA-224withECDSA";
        algorithms["ECDSAWITHSHA-224"] = "SHA-224withECDSA";
        algorithms["SHA224WITHECDSA"] = "SHA-224withECDSA";
        algorithms["SHA-224WITHECDSA"] = "SHA-224withECDSA";
        algorithms[X9ObjectIdentifiers.ECDsaWithSha224.Id] = "SHA-224withECDSA";

        algorithms["SHA256/ECDSA"] = "SHA-256withECDSA";
        algorithms["SHA-256/ECDSA"] = "SHA-256withECDSA";
        algorithms["ECDSAWITHSHA256"] = "SHA-256withECDSA";
        algorithms["ECDSAWITHSHA-256"] = "SHA-256withECDSA";
        algorithms["SHA256WITHECDSA"] = "SHA-256withECDSA";
        algorithms["SHA-256WITHECDSA"] = "SHA-256withECDSA";
        algorithms[X9ObjectIdentifiers.ECDsaWithSha256.Id] = "SHA-256withECDSA";

        algorithms["SHA384/ECDSA"] = "SHA-384withECDSA";
        algorithms["SHA-384/ECDSA"] = "SHA-384withECDSA";
        algorithms["ECDSAWITHSHA384"] = "SHA-384withECDSA";
        algorithms["ECDSAWITHSHA-384"] = "SHA-384withECDSA";
        algorithms["SHA384WITHECDSA"] = "SHA-384withECDSA";
        algorithms["SHA-384WITHECDSA"] = "SHA-384withECDSA";
        algorithms[X9ObjectIdentifiers.ECDsaWithSha384.Id] = "SHA-384withECDSA";

        algorithms["SHA512/ECDSA"] = "SHA-512withECDSA";
        algorithms["SHA-512/ECDSA"] = "SHA-512withECDSA";
        algorithms["ECDSAWITHSHA512"] = "SHA-512withECDSA";
        algorithms["ECDSAWITHSHA-512"] = "SHA-512withECDSA";
        algorithms["SHA512WITHECDSA"] = "SHA-512withECDSA";
        algorithms["SHA-512WITHECDSA"] = "SHA-512withECDSA";
        algorithms[X9ObjectIdentifiers.ECDsaWithSha512.Id] = "SHA-512withECDSA";

        algorithms["RIPEMD160/ECDSA"] = "RIPEMD160withECDSA";
        algorithms["ECDSAWITHRIPEMD160"] = "RIPEMD160withECDSA";
        algorithms["RIPEMD160WITHECDSA"] = "RIPEMD160withECDSA";
        algorithms[TeleTrusTObjectIdentifiers.ECSignWithRipeMD160.Id] = "RIPEMD160withECDSA";

        algorithms["GOST-3410"] = "GOST3410";
        algorithms["GOST-3410-94"] = "GOST3410";
        algorithms["GOST3411WITHGOST3410"] = "GOST3410";
        algorithms[CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94.Id] = "GOST3410";

        algorithms["ECGOST-3410"] = "ECGOST3410";
        algorithms["ECGOST-3410-2001"] = "ECGOST3410";
        algorithms["GOST3411WITHECGOST3410"] = "ECGOST3410";
        algorithms[CryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001.Id] = "ECGOST3410";
        return algorithms;
    }
}