using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

public class RSAHelper : RSARoot
{
    #region 私钥加密
    /// <summary>
    /// 基于BouncyCastle的RSA私钥加密
    /// </summary>
    /// <param name="privateKeyJava"></param>
    /// <param name="data"></param>
    /// <returns></returns>
    public static string EncryptPrivateKeyJava(string privateKeyJava, string data, string encoding = "UTF-8")
    {
        RsaKeyParameters privateKeyParam = (RsaKeyParameters)PrivateKeyFactory.CreateKey(Convert.FromBase64String(privateKeyJava));
        byte[] cipherbytes = Encoding.GetEncoding(encoding).GetBytes(data);
        RsaEngine rsa = new RsaEngine();
        rsa.Init(true, privateKeyParam);//参数true表示加密/false表示解密。
        cipherbytes = rsa.ProcessBlock(cipherbytes, 0, cipherbytes.Length);
        return Convert.ToBase64String(cipherbytes);
    }
    #endregion

    #region  公钥解密
    /// <summary>
    /// 基于BouncyCastle的RSA公钥解密
    /// </summary>
    /// <param name="publicKeyJava"></param>
    /// <param name="data"></param>
    /// <param name="encoding"></param>
    /// <returns></returns>
    public static string DecryptPublicKeyJava(string publicKeyJava, string data, string encoding = "UTF-8")
    {
        RsaKeyParameters publicKeyParam = (RsaKeyParameters)PublicKeyFactory.CreateKey(Convert.FromBase64String(publicKeyJava));
        byte[] cipherbytes = Convert.FromBase64String(data);
        RsaEngine rsa = new RsaEngine();
        rsa.Init(false, publicKeyParam);//参数true表示加密/false表示解密。
        cipherbytes = rsa.ProcessBlock(cipherbytes, 0, cipherbytes.Length);
        return Encoding.GetEncoding(encoding).GetString(cipherbytes);
    }
    #endregion

    #region 加签
    /// <summary>
    /// 基于BouncyCastle的RSA签名
    /// </summary>
    /// <param name="data"></param>
    /// <param name="privateKeyJava"></param>
    /// <param name="hashAlgorithm">JAVA的和.NET的不一样，如：MD5(.NET)等同于MD5withRSA(JAVA)</param>
    /// <param name="encoding"></param>
    /// <returns></returns>
    public static string RSASignJavaBouncyCastle(string data, string privateKeyJava, string hashAlgorithm = "MD5withRSA", string encoding = "UTF-8")
    {
        RsaKeyParameters privateKeyParam = (RsaKeyParameters)PrivateKeyFactory.CreateKey(Convert.FromBase64String(privateKeyJava));
        ISigner signer = SignerUtilities.GetSigner(hashAlgorithm);
        signer.Init(true, privateKeyParam);//参数为true验签，参数为false加签
        var dataByte = Encoding.GetEncoding(encoding).GetBytes(data);
        signer.BlockUpdate(dataByte, 0, dataByte.Length);
        //return Encoding.GetEncoding(encoding).GetString(signer.GenerateSignature()); //签名结果 非Base64String
        return Convert.ToBase64String(signer.GenerateSignature());
    }
    #endregion

    #region 验签
    /// <summary>
    /// 基于BouncyCastle的RSA验证签名
    /// </summary>
    /// <param name="data">源数据</param>
    /// <param name="publicKeyJava"></param>
    /// <param name="signature">base64签名</param>
    /// <param name="hashAlgorithm">JAVA的和.NET的不一样，如：MD5(.NET)等同于MD5withRSA(JAVA)</param>
    /// <param name="encoding"></param>
    /// <returns></returns>
    public static bool VerifyJavaBouncyCastle(string data, string publicKeyJava, string signature, string hashAlgorithm = "MD5withRSA", string encoding = "UTF-8")
    {
        RsaKeyParameters publicKeyParam = (RsaKeyParameters)PublicKeyFactory.CreateKey(Convert.FromBase64String(publicKeyJava));
        ISigner signer = SignerUtilities.GetSigner(hashAlgorithm);
        signer.Init(false, publicKeyParam);
        byte[] dataByte = Encoding.GetEncoding(encoding).GetBytes(data);
        signer.BlockUpdate(dataByte, 0, dataByte.Length);
        //byte[] signatureByte = Encoding.GetEncoding(encoding).GetBytes(signature);// 非Base64String
        byte[] signatureByte = Convert.FromBase64String(signature);
        return signer.VerifySignature(signatureByte);
    }
    #endregion
}
