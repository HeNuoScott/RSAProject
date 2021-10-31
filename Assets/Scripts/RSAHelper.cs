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
    #region ˽Կ����
    /// <summary>
    /// ����BouncyCastle��RSA˽Կ����
    /// </summary>
    /// <param name="privateKeyJava"></param>
    /// <param name="data"></param>
    /// <returns></returns>
    public static string EncryptPrivateKeyJava(string privateKeyJava, string data, string encoding = "UTF-8")
    {
        RsaKeyParameters privateKeyParam = (RsaKeyParameters)PrivateKeyFactory.CreateKey(Convert.FromBase64String(privateKeyJava));
        byte[] cipherbytes = Encoding.GetEncoding(encoding).GetBytes(data);
        RsaEngine rsa = new RsaEngine();
        rsa.Init(true, privateKeyParam);//����true��ʾ����/false��ʾ���ܡ�
        cipherbytes = rsa.ProcessBlock(cipherbytes, 0, cipherbytes.Length);
        return Convert.ToBase64String(cipherbytes);
    }
    #endregion

    #region  ��Կ����
    /// <summary>
    /// ����BouncyCastle��RSA��Կ����
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
        rsa.Init(false, publicKeyParam);//����true��ʾ����/false��ʾ���ܡ�
        cipherbytes = rsa.ProcessBlock(cipherbytes, 0, cipherbytes.Length);
        return Encoding.GetEncoding(encoding).GetString(cipherbytes);
    }
    #endregion

    #region ��ǩ
    /// <summary>
    /// ����BouncyCastle��RSAǩ��
    /// </summary>
    /// <param name="data"></param>
    /// <param name="privateKeyJava"></param>
    /// <param name="hashAlgorithm">JAVA�ĺ�.NET�Ĳ�һ�����磺MD5(.NET)��ͬ��MD5withRSA(JAVA)</param>
    /// <param name="encoding"></param>
    /// <returns></returns>
    public static string RSASignJavaBouncyCastle(string data, string privateKeyJava, string hashAlgorithm = "MD5withRSA", string encoding = "UTF-8")
    {
        RsaKeyParameters privateKeyParam = (RsaKeyParameters)PrivateKeyFactory.CreateKey(Convert.FromBase64String(privateKeyJava));
        ISigner signer = SignerUtilities.GetSigner(hashAlgorithm);
        signer.Init(true, privateKeyParam);//����Ϊtrue��ǩ������Ϊfalse��ǩ
        var dataByte = Encoding.GetEncoding(encoding).GetBytes(data);
        signer.BlockUpdate(dataByte, 0, dataByte.Length);
        //return Encoding.GetEncoding(encoding).GetString(signer.GenerateSignature()); //ǩ����� ��Base64String
        return Convert.ToBase64String(signer.GenerateSignature());
    }
    #endregion

    #region ��ǩ
    /// <summary>
    /// ����BouncyCastle��RSA��֤ǩ��
    /// </summary>
    /// <param name="data">Դ����</param>
    /// <param name="publicKeyJava"></param>
    /// <param name="signature">base64ǩ��</param>
    /// <param name="hashAlgorithm">JAVA�ĺ�.NET�Ĳ�һ�����磺MD5(.NET)��ͬ��MD5withRSA(JAVA)</param>
    /// <param name="encoding"></param>
    /// <returns></returns>
    public static bool VerifyJavaBouncyCastle(string data, string publicKeyJava, string signature, string hashAlgorithm = "MD5withRSA", string encoding = "UTF-8")
    {
        RsaKeyParameters publicKeyParam = (RsaKeyParameters)PublicKeyFactory.CreateKey(Convert.FromBase64String(publicKeyJava));
        ISigner signer = SignerUtilities.GetSigner(hashAlgorithm);
        signer.Init(false, publicKeyParam);
        byte[] dataByte = Encoding.GetEncoding(encoding).GetBytes(data);
        signer.BlockUpdate(dataByte, 0, dataByte.Length);
        //byte[] signatureByte = Encoding.GetEncoding(encoding).GetBytes(signature);// ��Base64String
        byte[] signatureByte = Convert.FromBase64String(signature);
        return signer.VerifySignature(signatureByte);
    }
    #endregion
}
